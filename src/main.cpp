#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
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
#include <iostream>
#include <string>
#include <thread>


namespace beast = boost::beast;
namespace http = beast::http;     
namespace net = boost::asio;      
namespace ssl = net::ssl;       
using tcp = net::ip::tcp;  


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
    RSA* rsa_public_key = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!rsa_public_key) {
        std::cerr << "Failed to create RSA public key: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return "";
    }

    std::string encrypted(RSA_size(rsa_public_key), '\0');
    int result = RSA_public_encrypt(
        message.size(),
        reinterpret_cast<const unsigned char*>(message.c_str()),
        reinterpret_cast<unsigned char*>(&encrypted[0]),
        rsa_public_key,
        RSA_PKCS1_OAEP_PADDING
    );

    RSA_free(rsa_public_key);

    if (result == -1) {
        std::cerr << "Encryption failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return "";
    }

    return encrypted;
}


void handle_request(
    http::request<http::string_body> const& req,
    http::response<http::string_body>& res
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
            std::string message = "Authenticated message";
            std::string encrypted_message = encrypt(message, public_key);

            if (!encrypted_message.empty()) {
                res.body() = "Encrypted message: " + encrypted_message;
            } else {
                res.body() = "Failed to encrypt message";
            }
        } else {
            res.body() = "JWT verification failed";
        }

        // auto decoded_token = jwt::decode(jwt_token);
        // std::string payload = decoded_token.get_payload();

        // res.body() = "JWT and Public Key received and processed";
        

    } catch (const std::exception& e) {
        std::cerr << "Error decoding JWT: " << e.what() << std::endl;
        res.body() = "Invalid JWT";
    }

    res.set(http::field::content_type, "text/plain");
    res.prepare_payload();
}


int main() {
    std::cout << "Hello from the server!" << std::endl;

    try {
        net::io_context ioc;
        ssl::context ctx(ssl::context::sslv23);

        ctx.use_certificate_file("../cert.pem", ssl::context::pem);
        ctx.use_rsa_private_key_file("../key.pem", ssl::context::pem);

        tcp::acceptor acceptor(ioc, {tcp::v4(), 4433});
        bool shutdown_flag = false;

        while (!shutdown_flag) {
            tcp::socket socket(ioc);
            acceptor.accept(socket);

            beast::ssl_stream<tcp::socket> stream(std::move(socket), ctx);
            stream.handshake(ssl::stream_base::server);

            beast::flat_buffer buffer;
            http::request<http::string_body> req;
            http::read(stream, buffer, req);

            http::response<http::string_body> res{http::status::ok, req.version()};
            handle_request(req, res);

            http::write(stream, res);
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}