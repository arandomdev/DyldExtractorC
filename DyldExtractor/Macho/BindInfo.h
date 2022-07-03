#ifndef __MACHO_BINDINFO__
#define __MACHO_BINDINFO__

#include <coroutine>
#include <exception>
#include <mach-o/loader.h>

namespace Macho {

template <typename T> struct Generator {
  struct promise_type;
  using handle_type = std::coroutine_handle<promise_type>;

  struct promise_type { // required
    T value_;
    std::exception_ptr exception_;

    Generator get_return_object() {
      return Generator(handle_type::from_promise(*this));
    }
    std::suspend_always initial_suspend() { return {}; }
    std::suspend_always final_suspend() noexcept { return {}; }
    void unhandled_exception() {
      exception_ = std::current_exception();
    }                                      // saving exception
    template <std::convertible_to<T> From> // C++20 concept
    std::suspend_always yield_value(From &&from) {
      value_ = std::forward<From>(from); // caching the result in promise
      return {};
    }
    void return_void() {}
  };

  handle_type h_;

  Generator(handle_type h) : h_(h) {}
  ~Generator() { h_.destroy(); }
  explicit operator bool() {
    fill(); // The only way to reliably find out whether or not we finished
            // coroutine, whether or not there is going to be a next value
            // generated (co_yield) in coroutine via C++ getter (operator ()
            // below) is to execute/resume coroutine until the next co_yield
            // point (or let it fall off end). Then we store/cache result in
            // promise to allow getter (operator() below to grab it without
            // executing coroutine)
    return !h_.done();
  }
  T operator()() {
    fill();
    full_ = false; // we are going to move out previously cached result to
                   // make promise empty again
    return std::move(h_.promise().value_);
  }

private:
  bool full_ = false;

  void fill() {
    if (!full_) {
      h_();
      if (h_.promise().exception_)
        std::rethrow_exception(h_.promise().exception_);
      // propagate coroutine exception in called context

      full_ = true;
    }
  }
};

struct BindRecord {
  uint8_t segIndex = 0;
  uint64_t segOffset = 0;
  uint8_t type = 0;
  uint8_t flags = 0;
  int libOrdinal = 0;
  char *symbolName = nullptr;
  uint64_t addend = 0;
};

template <class P>
Generator<BindRecord> BindInfoReader(const uint8_t *start, const uint8_t *end);
//

} // namespace Macho

#endif // __MACHO_BINDINFO__