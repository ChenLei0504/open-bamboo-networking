// TLS handshake smoke test over an in-memory BIO pair.
//
// Guards against the MSVC ARM64 /O2 /Gs0 OpenSSL codegen defect: the prologue
// of tls_parse_all_extensions called __chkstk before spilling x30, so the
// function returned into its own prologue and OrcaSlicer crashed during the
// Bambu cloud MQTT login (persano/open-bambu-networking-plugin#10,
// openssl/openssl#26239). A real TLS 1.3 handshake, both ends in this
// process, exercises that function on every CI platform.

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

// Self-signed, CN=localhost, generated for this test (expires 2036-11-13).
const char kCertPem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDCTCCAfGgAwIBAgIUHu9yU63rxC0yDq7n/HDAxmyLH4gwDQYJKoZIhvcNAQEL\n"
    "BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTExMzE4NTMxMFoXDTM2MTEx\n"
    "MDE4NTMxMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\n"
    "AAOCAQ8AMIIBCgKCAQEA27//FBa2I8ljnFV7Rk53SyM/6vk5JywyRsMY3S+/5cC2\n"
    "0UrTdPpIw1toGaSe8sKNvCZOop0VSDBLOkmIpokGHmXXPVR5w5NsBB03Fx33yCsi\n"
    "lxzQnZY2zgF31bbwc29qZ/QEVfF5yxLEl2s6LZPOFAIPtfa2okaAzD9x5x1b5r6e\n"
    "4svSz1jjrUshyQaABN03LelN4ylSi6QPg+ljiVuKfawoWzW1O+/YTASurVd4FeMS\n"
    "mWmFElSSpcQ6DhnPGz900qwyVDrfRkZjPEhZUk48brrT8I1bEvi5b0hAeMYbqpkJ\n"
    "lvC0t5zqugwl/mbuvRt/D+HMLa4LLA0NKpNI8h60QQIDAQABo1MwUTAdBgNVHQ4E\n"
    "FgQU/ci+Oc3AfBgvPObEcEVCSBereZwwHwYDVR0jBBgwFoAU/ci+Oc3AfBgvPObE\n"
    "cEVCSBereZwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEANyVT\n"
    "bcNmuzuB0CMCA+1tyo1H8O83PJTkZvDZsoUmNKhfJ+dAhtKOkdpM8xT3QD4jhYSL\n"
    "Ojyez0IHsO7XoXIcFwwSsSvVXHJT+hOlUlXQb4lvUDYiPTfQd2BymLUSnRJT5dJY\n"
    "WtdDtFLLhft08tTZKKpeGUMMM0D8fBWCtiBE4hVLx+ddJZQ/F4JL9MsGaTMsm7+f\n"
    "Q7LGa8K+DjZ3GKF7NjelSotwRxDN8goZKkXK2zuxgEIbwNVK8tdSevIssoBAkGAV\n"
    "9hQWN9uF1a0v347mOtuB29YWBsST0MoLpmn9MeEcUjNVzZuMlAwONlWpgUMSOEYL\n"
    "6cF57AYoqbhEdWmenA==\n"
    "-----END CERTIFICATE-----\n";

const char kKeyPem[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDbv/8UFrYjyWOc\n"
    "VXtGTndLIz/q+TknLDJGwxjdL7/lwLbRStN0+kjDW2gZpJ7ywo28Jk6inRVIMEs6\n"
    "SYimiQYeZdc9VHnDk2wEHTcXHffIKyKXHNCdljbOAXfVtvBzb2pn9ARV8XnLEsSX\n"
    "azotk84UAg+19raiRoDMP3HnHVvmvp7iy9LPWOOtSyHJBoAE3Tct6U3jKVKLpA+D\n"
    "6WOJW4p9rChbNbU779hMBK6tV3gV4xKZaYUSVJKlxDoOGc8bP3TSrDJUOt9GRmM8\n"
    "SFlSTjxuutPwjVsS+LlvSEB4xhuqmQmW8LS3nOq6DCX+Zu69G38P4cwtrgssDQ0q\n"
    "k0jyHrRBAgMBAAECggEAKZD5ImcjX8SNw3oF3egkt4E862jl7yt0fR8VOm14SnC4\n"
    "BAG32tYm4lENcWBKspercK38TNUSu/tql2VmZD3h+uj/nDm46I4fre2KyKQiBOpn\n"
    "2haYvV43EqODc9jtRaCLC4vEMC+Dfq6Xoh6lvA5LukwjhaNbq3lTjo7nsDRE+HG3\n"
    "WIT56ilGMlaZDUE6+i1n2FCWI7LRces6hUu1owpnjISw3nQSCIb0psIXb6MUqfIs\n"
    "clAyuu1Ared+b0aW6y7qur4jY3fuVs/3rWcDhiZYNBiggzju/efDenOCkIaU6Izo\n"
    "zY4PO3nSq9KU5H8O22PFm5sKjA9iPljCWDBwY+SrEwKBgQD2MXInu/l5YEfw63zN\n"
    "dW0XWqTFLJkSWWjxGFozBOS01aKeJAZjOoJTM65cupVNQXvBvZu+P/9MphM91kT3\n"
    "jfyIeKXWXSGDFRP5XdSVyVfWsAv/kAxB9ZYT5APhQbEqO4N6mjy9D6Oq4m/Qj4UV\n"
    "JNP1Nr/EGKxx3c4YXCvAbaXANwKBgQDkgOV6EWrT7aaC8h7/1pVDwOEhpgM44YCs\n"
    "ME6QSqP8c2yFvdyNKyyMVtJy/tbFUbeWph5bHSGfhIEud3ouHXh+ZGT1bkzgxDnD\n"
    "+M8qpwCHn8BRmOyFJ11ktK7RL+786cPjDDb4qtUoo0lCu2fOP4obY3iJEOiQRsKH\n"
    "tUl2uuhDRwKBgQCNMKRIN1yGiHoZp+PGLO7octqGHeKXjGFLy2yHT+od71s4mG51\n"
    "X+u37a60jWjsin6ACM6V2DwA6EmmsAiTdIF8fryU6Io8k80FuRMe5/6RKBtpcGIn\n"
    "PcHZHG5BNBx3nPP1TxlAUATMDtqTYIuxKZLJUaG+w2u6TbtRayLIU9m4FwKBgG6N\n"
    "3nj8zE7VAGcCdfUaAQXS4BnDlHOExxiIFrrBIi4WOj9K6NZ0OQ19RDzXB1pYexas\n"
    "MKusoIPpPAcbT0XYhF/CewYz44Yr6jbivnjIa/0yUX4pGuYhcZIzyRD0vBApmdjU\n"
    "JBSTsqYCuoNK4KJtI4i0y7ClOZ/0XFIEaBLFw3IpAoGBAPXAoahhqzx2GV3PahFo\n"
    "BX+/Hn3zeTwJI9rY+A4gjh+DHmH0u1tY+Ku8u1QkmAFS/o3765yAyLBR0AmPPRnv\n"
    "1S3EeemAkhJEdD3FAMheDVwp5CBh8XTCCsTtV3fbInh37gLQ/uuFsh95/Y5hLE9P\n"
    "Z4n6PY9E28x3X3G2C8KleNdz\n"
    "-----END PRIVATE KEY-----\n";

[[noreturn]] void fail(const char* what) {
    std::fprintf(stderr, "tls_handshake: %s\n", what);
    ERR_print_errors_fp(stderr);
    std::exit(1);
}

bool want_retry(int ret, SSL* ssl) {
    switch (SSL_get_error(ssl, ret)) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        return true;
    default:
        return false;
    }
}

// One full TLS 1.3 handshake plus a ping/pong exchange.
void handshake_once(SSL_CTX* client_ctx, SSL_CTX* server_ctx) {
    BIO* to_server = nullptr;
    BIO* to_client = nullptr;
    if (!BIO_new_bio_pair(&to_server, 0, &to_client, 0))
        fail("BIO_new_bio_pair");

    SSL* client = SSL_new(client_ctx);
    SSL* server = SSL_new(server_ctx);
    if (!client || !server) fail("SSL_new");
    SSL_set_bio(client, to_server, to_server);
    SSL_set_bio(server, to_client, to_client);
    SSL_set_connect_state(client);
    SSL_set_accept_state(server);

    bool client_done = false, server_done = false;
    for (int round = 0; round < 32 && !(client_done && server_done); ++round) {
        if (!client_done) {
            int rc = SSL_do_handshake(client);
            if (rc == 1)
                client_done = true;
            else if (!want_retry(rc, client))
                fail("client handshake");
        }
        if (!server_done) {
            int rc = SSL_do_handshake(server);
            if (rc == 1)
                server_done = true;
            else if (!want_retry(rc, server))
                fail("server handshake");
        }
    }
    if (!client_done || !server_done) fail("handshake did not finish");

    if (SSL_write(client, "ping", 4) != 4) fail("client write");
    char buf[8] = {};
    if (SSL_read(server, buf, sizeof(buf)) != 4 || std::memcmp(buf, "ping", 4) != 0)
        fail("server read");
    if (SSL_write(server, "pong", 4) != 4) fail("server write");
    std::memset(buf, 0, sizeof(buf));
    if (SSL_read(client, buf, sizeof(buf)) != 4 || std::memcmp(buf, "pong", 4) != 0)
        fail("client read");

    SSL_free(client);  // takes ownership of to_server
    SSL_free(server);  // takes ownership of to_client
}

SSL_CTX* make_ctx(bool server) {
    SSL_CTX* ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (!ctx) fail("SSL_CTX_new");
    // TLS 1.3 only: the extension parsing under test runs on both roles.
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1)
        fail("pin TLS1.3");
    if (!server) {
        // Self-signed fixture: trust is not what this test exercises.
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        return ctx;
    }
    BIO* cert_bio = BIO_new_mem_buf(kCertPem, -1);
    BIO* key_bio  = BIO_new_mem_buf(kKeyPem, -1);
    X509* cert    = cert_bio ? PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr) : nullptr;
    EVP_PKEY* key =
        key_bio ? PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr) : nullptr;
    if (!cert || !key) fail("load fixture key/cert");
    if (SSL_CTX_use_certificate(ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey(ctx, key) != 1)
        fail("install fixture key/cert");
    X509_free(cert);
    EVP_PKEY_free(key);
    BIO_free(cert_bio);
    BIO_free(key_bio);
    return ctx;
}

}  // namespace

int main() {
    SSL_CTX* client_ctx = make_ctx(false);
    SSL_CTX* server_ctx = make_ctx(true);
    for (int i = 0; i < 3; ++i) handshake_once(client_ctx, server_ctx);
    SSL_CTX_free(client_ctx);
    SSL_CTX_free(server_ctx);
    std::printf("tls_handshake: ok (3x TLS 1.3 handshake + ping/pong)\n");
    return 0;
}
