#pragma once

#include <optional>
#include <string>
#include <utility>

#include "idr/common/error.hpp"

namespace idr {

template <class T>
class Result {
public:
    static Result ok(T value) {
        Result r;
        r.opt_ = std::move(value);
        r.code_ = ErrorCode::ok;
        return r;
    }

    static Result err(ErrorCode code, std::string message = "") {
        Result r;
        r.code_ = code;
        r.message_ = std::move(message);
        return r;
    }

    bool has_value() const { return opt_.has_value(); }

    T& value() { return *opt_; }
    const T& value() const { return *opt_; }

    ErrorCode error() const { return code_; }
    const std::string& message() const { return message_; }

private:
    Result() = default;

    std::optional<T> opt_;
    ErrorCode code_ = ErrorCode::ok;
    std::string message_;
};

// Result<void> for operations that only report success/failure.
template <>
class Result<void> {
public:
    static Result ok() {
        Result r;
        r.ok_ = true;
        return r;
    }

    static Result err(ErrorCode code, std::string message = "") {
        Result r;
        r.ok_ = false;
        r.code_ = code;
        r.message_ = std::move(message);
        return r;
    }

    bool has_value() const { return ok_; }

    void value() const {}

    ErrorCode error() const { return code_; }
    const std::string& message() const { return message_; }

private:
    Result() = default;

    bool ok_ = false;
    ErrorCode code_ = ErrorCode::ok;
    std::string message_;
};

}  // namespace idr
