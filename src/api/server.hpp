#pragma once

#ifdef WITH_API

#include "../config/config.hpp"

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace httplib {
class Request;
class Response;
}

namespace keen_pbr3 {

// HTTP limits passed to cpp-httplib (api.max_request_body_bytes and the
// api.*_timeout_seconds keys); httplib's own 5 s timeouts are too tight for
// a browser on a slow link, an unbounded body is not.
struct ApiServerLimits {
    std::size_t max_request_body_bytes{1024U * 1024U};
    int read_timeout_seconds{15};
    int write_timeout_seconds{15};
    int keep_alive_timeout_seconds{20};
};

ApiServerLimits api_server_limits(const ApiConfig& config);

// CSRF guard for the unauthenticated API. A request without an Origin header
// (curl, router scripts) is always allowed. With one it must be the origin
// the request was sent to (http://<Host> or https://<Host>) or one of
// `allowed_origins` (api.cors.allowed_origins, exact match).
// `cross_origin_allowed` tells whether CORS response headers are needed.
bool api_request_origin_allowed(const std::string& origin,
                                const std::string& host,
                                const std::vector<std::string>& allowed_origins,
                                bool& cross_origin_allowed);

class ApiError : public std::runtime_error {
public:
    explicit ApiError(std::string message,
                      int status = 500,
                      std::optional<std::string> body = std::nullopt)
        : std::runtime_error(std::move(message))
        , status_(status)
        , body_(std::move(body)) {}

    int status() const noexcept {
        return status_;
    }

    const std::optional<std::string>& body() const noexcept {
        return body_;
    }

private:
    int status_;
    std::optional<std::string> body_;
};

// HTTP REST API server using cpp-httplib.
// Runs in a background thread and integrates with the Daemon event loop
// for shutdown coordination.
class ApiServer {
public:
    // Construct with listen address from ApiConfig.
    // Does not start listening until start() is called.
    explicit ApiServer(const ApiConfig& config);
    ~ApiServer();

    // Non-copyable, non-movable
    ApiServer(const ApiServer&) = delete;
    ApiServer& operator=(const ApiServer&) = delete;
    ApiServer(ApiServer&&) = delete;
    ApiServer& operator=(ApiServer&&) = delete;

    // Register route handlers before calling start().
    using RouteHandler = std::function<std::string()>;
    using BodyRouteHandler = std::function<std::string(const std::string& body)>;
    using StreamRouteHandler = std::function<void(const httplib::Request&,
                                                  httplib::Response&)>;

    // Register a GET handler that returns a JSON string.
    void get(const std::string& path, RouteHandler handler);

    // Register a POST handler that returns a JSON string.
    void post(const std::string& path, RouteHandler handler);

    // Register a POST handler that receives the request body and returns a JSON string.
    void post(const std::string& path, BodyRouteHandler handler);

    // Register a GET handler that streams a non-JSON response.
    void get_stream(const std::string& path, StreamRouteHandler handler);

    // Register static file serving from frontend_root for non-/api routes.
    // Returns false if static serving could not be configured.
    bool register_static_root(const std::string& frontend_root);

    // Start listening in a background thread.
    void start();

    // Stop the server and join the background thread.
    void stop();

    // Returns true if the server is currently listening.
    bool listening() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace keen_pbr3

#endif // WITH_API
