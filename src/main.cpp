#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/write.hpp>
#include <jsoncpp/json/json.h>
#include <jwt-cpp/jwt.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <thread>
#include <csignal>


namespace beast = boost::beast;
namespace http = beast::http;     
namespace net = boost::asio;      
namespace ssl = net::ssl;
namespace fs = std::filesystem;
using tcp = net::ip::tcp;  


// Function to print a buffer as a hex string
void print_hex(const unsigned char* buffer, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i];
    }
    std::cout << std::dec << std::endl;
}


std::string get_config(
    const std::string& file_path
) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open JSON file");
    }

    Json::Value root;
    file >> root;
    file.close();

    Json::StreamWriterBuilder writer;

    return Json::writeString(writer, root);
}


bool verify_token(
    const std::string& token, 
    const std::string& public_key
) {
    try {
        auto decoded_token = jwt::decode(token);

        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::rs256(public_key, "", "", ""))
            .with_issuer("https://securetoken.google.com/YOUR_PROJECT_ID");

        verifier.verify(decoded_token);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "JWT verification failed: " << e.what() << std::endl;
        return false;
    }
}


bool generate_aes_key(
    unsigned char* key, 
    unsigned char* iv, 
    int key_length
) {
    if (!RAND_bytes(key, key_length) || !RAND_bytes(iv, AES_BLOCK_SIZE)) {
        std::cerr << "Failed to generate AES key or IV" << std::endl;
        return false;
    }
    return true;
}


std::string base64_encode(
    const std::string& input
) {
    BIO* bio = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    bio = BIO_push(bio, bmem);

    BIO_write(bio, input.data(), input.size());
    BIO_flush(bio);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);

    std::string output(bptr->data, bptr->length - 1);
    BIO_free_all(bio);

    return output;
}


std::string encrypt_aes(
    const std::string& data, 
    const unsigned char* key, 
    unsigned char* iv
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create EVP_CIPHER_CTX" << std::endl;
        return "";
    }

    int len;
    int ciphertext_len;
    unsigned char ciphertext[data.size() + AES_BLOCK_SIZE];

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        std::cerr << "Failed to initialize AES Encyption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, reinterpret_cast<const unsigned char*>(data.c_str()), data.size()) != 1) {
        std::cerr << "Failed to encrypt data" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        std::cerr << "Failed to encrypt data" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return std::string(reinterpret_cast<char*>(ciphertext), ciphertext_len);
}


std::string encrypt_rsa(
    const std::string& data, 
    const std::string& public_key_pem
) {
    BIO* bio = BIO_new_mem_buf(public_key_pem.data(), -1);

    if (!bio) {
        std::cerr << "Failed to create BIO: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return "";
    }

    EVP_PKEY* evp_public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!evp_public_key) {
        std::cerr << "Failed to create EVP public key: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return "";
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(evp_public_key, nullptr);
    if (!ctx) {
        std::cerr << "Failed to create EVP context: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_PKEY_free(evp_public_key);
        return "";
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        std::cerr << "Failed to initialize encryption: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(evp_public_key);
        return "";
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        std::cerr << "Failed to set padding: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(evp_public_key);
        return "";
    }

    size_t outlen;
    if (EVP_PKEY_encrypt(
        ctx, 
        nullptr, 
        &outlen, 
        reinterpret_cast<const unsigned char*>(data.c_str()),
        data.size()) <= 0
    ) {
        std::cerr << "Failed to determine buffer length: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(evp_public_key);
        return "";
    }

    std::string encrypted(outlen, '\0');
    if (EVP_PKEY_encrypt(
        ctx,
        reinterpret_cast<unsigned char*>(&encrypted[0]),
        &outlen,
        reinterpret_cast<const unsigned char*>(data.c_str()),
        data.size()) <= 0
    ) {
        std::cerr << "Encryption failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(evp_public_key);
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evp_public_key);

    return encrypted;
}


void handle_request(
    http::request<http::string_body> const& req,
    http::response<http::string_body>& res,
    std::string& config
) {
    if (req[http::field::content_type] != "application/json") {
        res.result(http::status::bad_request);
        res.body() = "Invalid Content-Type";
        res.prepare_payload();
        return;
    }

    Json::CharReaderBuilder readerBuilder;
    Json::Value root;
    std::string errs;
    std::istringstream s(req.body());

    if (!Json::parseFromStream(readerBuilder, s, &root, &errs)) {
        res.result(http::status::bad_request);
        res.body() = "Invalid JSON";
        res.prepare_payload();
        return;
    }

    try {
        std::string jwt_token = root["jwt"].asString();
        std::string public_key = root["public_key"].asString();

        std::cout << "JWT received: " << jwt_token << std::endl;
        std::cout << "Public Key received: " << public_key << std::endl;

        if (verify_token(jwt_token, public_key)) {
            unsigned char sym_key[32];
            unsigned char iv[AES_BLOCK_SIZE];


            if (generate_aes_key(sym_key, iv, sizeof(sym_key))) {
                std::cout << "Generated AES key: ";
                print_hex(sym_key, sizeof(sym_key));
                std::cout << "Generated IV: ";
                print_hex(iv, AES_BLOCK_SIZE);
            } else {
                std::cerr << "Failed to generate AES key and IV" << std::endl;
                return;
            }


            // if (!generate_aes_key(sym_key, iv, sizeof(sym_key))) {
            //     res.body() = "Failed to generate symetrical key";
            //     res.prepare_payload();
            //     return;
            // }

            std::string encrypted_config = encrypt_aes(config, sym_key, iv);
            std::string encrypted_key = encrypt_rsa(std::string(reinterpret_cast<char*>(sym_key), sizeof(sym_key)), public_key);
            // std::string message = "Test message";

            if (!encrypted_config.empty() && !encrypted_key.empty()) {
                Json::Value response;
                response["encrypted_key"] = base64_encode(encrypted_key);
                response["iv"] = base64_encode(std::string(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE));
                response["encrypted_config"] = base64_encode(encrypted_config);

                // response["encrypted_key"] = base64_encode(encrypt_rsa(message, public_key));

                Json::StreamWriterBuilder writer;

                res.body() = Json::writeString(writer, response);
            } else {
                res.body() = "Failed to encrypt content";
            }
        } else {
            res.body() = "JWT verification failed";
        }

    } catch (const std::exception& e) {
        std::cerr << "Error decoding JWT: " << e.what() << std::endl;
        res.body() = "Invalid JWT";
    }

    res.set(http::field::content_type, "application/json");
    res.prepare_payload();
}


void do_accept(
    tcp::acceptor& acceptor, 
    ssl::context& ctx, 
    net::io_context& ioc, 
    std::string& config
) {
    acceptor.async_accept([&](boost::system::error_code ec, tcp::socket socket) {
        if (!ec) {
            std::make_shared<std::thread>([&, socket = std::move(socket)]() mutable {
                beast::ssl_stream<tcp::socket> stream(std::move(socket), ctx);
                boost::system::error_code ec;
                stream.handshake(ssl::stream_base::server, ec);

                if (!ec) {
                    beast::flat_buffer buffer;
                    http::request<http::string_body> req;
                    http::read(stream, buffer, req, ec);

                    if (!ec) {
                        http::response<http::string_body> res{http::status::ok, req.version()};
                        handle_request(req, res, config);

                        http::write(stream, res, ec);
                    }
                }

                stream.shutdown(ec);
                if (ec && ec != beast::errc::not_connected) {
                    std::cerr << "Shutdown failed: " << ec.message() << std::endl;
                }
            })->detach();
        }

        if (ec != net::error::operation_aborted) {
            do_accept(acceptor, ctx, ioc, config);
        }
    });
}


int main() {
    std::cout << "Server started..." << std::endl;

    try {
        net::io_context ioc;
        ssl::context ctx(ssl::context::sslv23);

        ctx.use_certificate_file("../cert.pem", ssl::context::pem);
        ctx.use_rsa_private_key_file("../key.pem", ssl::context::pem);

        tcp::acceptor acceptor(ioc, {tcp::v4(), 4433});

        net::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](boost::system::error_code const&, int) {
            std::cout << "Signal received, shutting down..." << std::endl;
            acceptor.close();
            ioc.stop(); 
        });

        fs::path root = "..";
        fs::path data_dir = "data";
        fs::path secrets_dir = "secrets";
        fs::path file_name = "config.json";

        fs::path path = root / data_dir / secrets_dir / file_name;

        std::string config = get_config(path.string());

        do_accept(acceptor, ctx, ioc, config);

        ioc.run();

        std::cout << "Server is shutting down..." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}