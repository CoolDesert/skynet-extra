#define LUA_LIB
#include <stdio.h>
#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

#include <lua.h>
#include <lauxlib.h>

/* SSL debug */
#define ENABLE_SSL_DEBUG_INFO

#ifdef ENABLE_SSL_DEBUG_INFO

#define SSL_WHERE_INFO(ssl, w, flag, msg) {							\
		if(w & flag) {												\
			printf("+ %s: ", name);									\
			printf("%20.20s", msg);									\
			printf(" - %30.30s ", SSL_state_string_long(ssl));		\
			printf(" - %5.10s ", SSL_state_string(ssl));			\
			printf("\n");											\
		}															\
	} 

static void
krx_ssl_info_callback(const SSL* ssl, int where, int ret, const char* name) {
	if(ret == 0) {
		printf("-- krx_ssl_info_callback: error occured.\n");
		return;
	}
	SSL_WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP");
	SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_START, "HANDSHAKE START");
	SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");
}

static void 
krx_ssl_server_info_callback(const SSL* ssl, int where, int ret) {
	krx_ssl_info_callback(ssl, where, ret, "server");
}

static void 
krx_ssl_client_info_callback(const SSL* ssl, int where, int ret) {
	krx_ssl_info_callback(ssl, where, ret, "client");
}

#endif


struct krx {
	SSL* ssl;                                                                           /* the SSL* which represents a "connection" */
	BIO* internal_bio;                                                                  /* we use memory read bios */
	BIO* network_bio;                                                                   /* we use memory write bios */
};

static int GLOBAL_SSL_LIB_REF = 0;


static int
krx_ssl_verify_peer(int ok, X509_STORE_CTX* ctx) {
	return 1;
}

static int
linit(lua_State *L) {
	if (++GLOBAL_SSL_LIB_REF == 1) {
		SSL_library_init();
		SSL_load_error_strings();
		ERR_load_BIO_strings();
		OpenSSL_add_all_algorithms();
		printf("SSL lib init! \n");
	}
	return 0;
}

static int
lcleanup(lua_State *L) {
	if (--GLOBAL_SSL_LIB_REF == 0) {
		ENGINE_cleanup();
		CONF_modules_unload(1);
		ERR_free_strings();
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
		printf("SSL lib cleanup! \n");
	}
	return 0;
}

static int
ldestroy(lua_State *L) {
	SSL_CTX **p = (SSL_CTX **)lua_touserdata(L, 1);
	printf("SSL_CTX_free : %p \n", *p);
	SSL_CTX_free(*p);
	*p = NULL;
	return 0;
}

static int
ltostring(lua_State *L) {
	struct krx * k = (struct krx*)lua_touserdata(L, 1);
	char tmp[128] = {0};
	int internal_pending = BIO_ctrl_pending(k->internal_bio);
	int network_pending = BIO_ctrl_pending(k->network_bio);
	int internal_wpending = BIO_ctrl_wpending(k->internal_bio);
	int network_wpending = BIO_ctrl_wpending(k->network_bio);
	int internal_want = BIO_ctrl_get_read_request(k->internal_bio);

	sprintf(tmp, "internal: %d %d, network: %d %d, want: %d",
						 internal_pending, internal_wpending, network_pending, network_wpending,
						 	internal_want);
	lua_pushstring(L, tmp);
	return 1;
}

static int
lshutdown(lua_State *L) {
	struct krx * k = (struct krx*)lua_touserdata(L, 1);	
	printf("shutdown ssl: %p \n", k);
	if (k->ssl) {
		/*
		SSL_free() also calls the free()ing procedures for indirectly affected items, 
		if applicable: the buffering BIO, the read and write BIOs, 
		cipher lists specially created for this ssl, the SSL_SESSION. 
		Do not explicitly free these indirectly freed up items before or after calling SSL_free(), 
		as trying to free things twice may lead to program failure.
		*/
		SSL_free(k->ssl);
		BIO_free(k->network_bio);
		k->ssl = NULL;
	}
	return 0;
}

static int
lctxnew(lua_State *L) {
	const char * certfile = luaL_checkstring(L, 1);
	const char * keyfile = luaL_checkstring(L, 2);
	//int isserver = lua_toboolean(L, 3);

	int r;

	/* create a new context using DTLS */
	//SSL_CTX *ctx = SSL_CTX_new(isserver ? TLS_server_method() : TLS_client_method());
	SSL_CTX *ctx = SSL_CTX_new(TLS_method());
	if(!ctx) {
		ERR_print_errors_fp(stderr);
		return luaL_error(L, "Error: cannot create SSL_CTX.");
	}
 
	/* set our supported ciphers */
	//r = SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
	// r = SSL_CTX_set_cipher_list(ctx, "TLSv1.2");
	// if(r != 1) {
	// 	ERR_print_errors_fp(stderr);
	// 	return luaL_error(L, "Error: cannot set the cipher list.");
	// }
 
	/* the client doesn't have to send it's certificate */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, krx_ssl_verify_peer);
 
	/* enable srtp */
	r = SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80");
	if(r != 0) {
		ERR_print_errors_fp(stderr);
		return luaL_error(L, "Error: cannot setup srtp.");
	}
 
	/* load key and certificate */
 
	/* certificate file; contains also the public key */
	r = SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM);
	if(r != 1) {
		ERR_print_errors_fp(stderr);
		return luaL_error(L, "Error: cannot load certificate file.");
	}
 
	/* load private key */
	r = SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM);
	if(r != 1) {
		ERR_print_errors_fp(stderr);
		return luaL_error(L, "Error: cannot load private key file.");
	}
 
	/* check if the private key is valid */
	r = SSL_CTX_check_private_key(ctx);
	if(r != 1) {
		ERR_print_errors_fp(stderr);
		return luaL_error(L, "Error: checking the private key failed.");
	}

	printf("SSL_CTX_new: %p\n", ctx);
	SSL_CTX ** p = (SSL_CTX **)lua_newuserdata(L, sizeof(SSL_CTX*));
	*p = ctx;

	lua_newtable(L);
	lua_pushcfunction(L, ldestroy);
	lua_setfield(L, -2, "__gc");
	lua_setmetatable(L, -2);
 
	return 1;
}

static int
lnew(lua_State *L) {
	SSL_CTX ** p = (SSL_CTX **)lua_touserdata(L, 1);
	if (*p == NULL) {
		return luaL_error(L, "Need SSL_ctx !");
	}
	SSL_CTX *ctx = *p;
	int isserver = lua_toboolean(L, 2);
	struct krx * k = (struct krx*)lua_newuserdata(L, sizeof(struct krx));

	/* create SSL* */
	k->ssl = SSL_new(ctx);
	if(!k->ssl) {
		return luaL_error(L, "Error: cannot create new SSL*.");
	}
 
#ifdef ENABLE_SSL_DEBUG_INFO

	/* info callback */
	if (isserver) {
		SSL_set_info_callback(k->ssl, krx_ssl_server_info_callback);
	} else {
		SSL_set_info_callback(k->ssl, krx_ssl_client_info_callback);
	}

#endif
 
	/* create bio pair */
	BIO_new_bio_pair(&k->internal_bio, 0, &k->network_bio, 0);
	SSL_set_bio(k->ssl, k->internal_bio, k->internal_bio);
 
	/* either use the server or client part of the protocol */
	if(isserver) {
		SSL_set_accept_state(k->ssl);
	} else {
		SSL_set_connect_state(k->ssl);
	}

	lua_newtable(L);
	lua_pushcfunction(L, ltostring);
	lua_setfield(L, -2, "__tostring");
	lua_pushcfunction(L, lshutdown);
	lua_setfield(L, -2, "__gc");
	lua_setmetatable(L, -2);

	printf("krx new: %p \n", k);
	return 1;
}

static int
lhandshake(lua_State *L) {
	struct krx * k = (struct krx*)lua_touserdata(L, 1);
	int ret = SSL_do_handshake(k->ssl);
	lua_pushinteger(L, ret);
	return 1;
}

static int
lsslwrite(lua_State *L) {
	struct krx * k = (struct krx*)lua_touserdata(L, 1);
	size_t len = 0;
	const char * data = luaL_checklstring(L, 2, &len);
	int ret = SSL_write(k->ssl, data, len);
	lua_pushinteger(L, ret);
	return 1;
}

static int
lbioread(lua_State *L) {
	struct krx * k = (struct krx*)lua_touserdata(L, 1);
	size_t pending = BIO_ctrl_pending(k->network_bio);
	if (pending > 0) {
		char buffer[pending];
		int read = BIO_read(k->network_bio, buffer, pending);
		lua_pushinteger(L, read);
		lua_pushlstring(L, buffer, read);
		return 2;
	} else {
		lua_pushinteger(L, 0);
		return 1;
	}
}

static int
lbiowrite(lua_State *L) {
	struct krx * k = (struct krx*)lua_touserdata(L, 1);
	size_t len = 0;
	const char * data = luaL_checklstring(L, 2, &len);
	int ret = BIO_write(k->network_bio, data, len);
	lua_pushinteger(L, ret);
	return 1;
}

static int
lsslread(lua_State *L) {
	struct krx * k = (struct krx*)lua_touserdata(L, 1);
	int need = luaL_optinteger(L, 2, 0);
	size_t pending = BIO_ctrl_pending(k->internal_bio);
	if (pending < need || pending == 0) {
	 	lua_pushinteger(L, 0);
	 	return 1;
	}
	if (need <= 0) {
		need = pending;
	}
	char buffer[need];
	int read = SSL_read(k->ssl, buffer, need);
	if (read > 0) {
		lua_pushinteger(L, read);
		lua_pushlstring(L, buffer, read);
		return 2;
	} else {
		lua_pushinteger(L, read);
		return 1;
	}
}

static int
lisinitfinished(lua_State *L) {
	struct krx * k = (struct krx*)lua_touserdata(L, 1);
	if (SSL_is_init_finished(k->ssl)) {
		lua_pushboolean(L, 1);
	} else {
		lua_pushboolean(L, 0);
	}
	return 1;
}

LUAMOD_API int
luaopen_ssl_core(lua_State *L) {
	luaL_checkversion(L);

	// init ssl lib
	linit(L);

	luaL_Reg l[] = {
		{ "ssl_ctx_new", lctxnew},
		{ "ssl_new", lnew},
		{ "ssl_do_handshake", lhandshake},
		{ "ssl_write", lsslwrite},
		{ "ssl_read", lsslread},
		{ "bio_write", lbiowrite},
		{ "bio_read", lbioread},
		{ "ssl_is_init_finished", lisinitfinished},
		{ NULL, NULL },
	};
	luaL_newlib(L,l);

	// cleanup ssl lib
	lua_newtable(L);
	lua_pushcfunction(L, lcleanup);
	lua_setfield(L, -2, "__gc");
	lua_setmetatable(L, -2);

	return 1;
}
