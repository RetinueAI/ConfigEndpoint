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
#include <openssl/evp.h>
#include <openssl/err.h>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <csignal>


namespace beast = boost::beast;
namespace http = beast::http;     
namespace net = boost::asio;      
namespace ssl = net::ssl;
namespace fs = std::filesystem;
using tcp = net::ip::tcp;  


std::string get_config(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open JSON file");
    }

    Json::Value root;
    file >> root;
    file.close();

    Json::StreamWriterBuilder writer;
    std::string json_string = Json::writeString(writer, root);

    return json_string;
}


bool verify_token(const std::string& token, const std::string& public_key) {
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


std::string encrypt(const std::string& message, const std::string& public_key_pem) {
    BIO* bio = BIO_new_mem_buf(public_key_pem.data(), -1);
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
        reinterpret_cast<const unsigned char*>(message.c_str()),
        message.size()) <= 0
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
        reinterpret_cast<const unsigned char*>(message.c_str()),
        message.size()) <= 0
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
            std::string encrypted_config = encrypt(config, public_key);

            if (!encrypted_config.empty()) {
                res.body() = encrypted_config;
            } else {
                res.body() = "Failed to encrypt message";
            }
        } else {
            res.body() = "JWT verification failed";
        }

    } catch (const std::exception& e) {
        std::cerr << "Error decoding JWT: " << e.what() << std::endl;
        res.body() = "Invalid JWT";
    }

    res.set(http::field::content_type, "text/plain");
    res.prepare_payload();
}


void do_accept(tcp::acceptor& acceptor, ssl::context& ctx, net::io_context& ioc, std::string& config) {
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

                // Gracefully close the stream
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

        tcp::acceptor acceptor(ioc, {tcp::v4(), 4434});

        // Set up signal handling
        net::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](boost::system::error_code const&, int) {
            std::cout << "Signal received, shutting down..." << std::endl;
            acceptor.close(); // Close the acceptor to stop accepting new connections
            ioc.stop(); // Stop the io_context
        });

        fs::path root = "..";
        fs::path data_dir = "data";
        fs::path secrets_dir = "secrets";
        fs::path file_name = "config.json";

        fs::path path = root / data_dir / secrets_dir / file_name;

        std::string config = get_config(path.string());

        do_accept(acceptor, ctx, ioc, config);

        ioc.run(); // Run the io_context to perform asynchronous operations

        std::cout << "Server is shutting down..." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}