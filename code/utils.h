#pragma once

class Input {
 public:
  Input() : ptr(nullptr), sz(0) {}
  Input(uint8_t* ptr, size_t sz) : ptr(ptr), sz(sz) {}

  char read_char() {
    if (sz < 1) {
      return '\x00';
    }

    char ret = *ptr;
    ptr += 1;
    sz -= 1;

    return ret;
  }

  int read_int() {
    if (sz < 4) {
      return 0;
    }

    int ret = *(int*)ptr;
    ptr += 4;
    sz -= 4;

    return ret;
  }

  std::string read_string() {
    unsigned int len = read_int();
    if (sz < len) {
      return "";
    }

    std::string ret(ptr, ptr + len);
    ptr += len;
    sz -= len;

    return ret;
  }

  std::string read_string_n(unsigned int n) {
    if (sz < n) {
      return "";
    }

    std::string ret(ptr, ptr + n);
    ptr += n;
    sz -= n;

    return ret;
  }

  int read_bytes_n(uint8_t* dst, unsigned int n) {
    if (sz < n) {
      return 0;
    }

    memcpy(dst, ptr, n);
    ptr += n;
    sz -= n;

    return n;
  }

 private:
  uint8_t* ptr;
  size_t sz;
};