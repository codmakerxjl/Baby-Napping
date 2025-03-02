/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdio.h>
#include <string.h>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <unordered_map>

#include "se_defines.h"

SE_GLOBALS()

class StateMachine {
  uint32_t state;
  std::unordered_map<uint32_t, std::unordered_map<char, uint32_t>> transitions;
  std::unordered_map<uint32_t, std::string> names;

 public:
  bool valid;

  StateMachine() : state(0), valid(true) {}
  void make_transition(uint32_t state, char input, uint32_t next_state) {
    transitions[state][input] = next_state;
  }
  void make_name(uint32_t state, std::string val) {
    names[state] = val;
  }

  std::optional<std::string> step(char x) {
    if (!valid) {
      return std::nullopt;
    }
    auto table = transitions.find(state);
    if (table == transitions.end()) {
      valid = false;
      return std::nullopt;
    }
    SE_STEP(true);
    auto new_state = table->second.find(x);
    if (new_state == table->second.end()) {
      valid = false;
      return std::nullopt;
    }
    SE_STEP(true);
    state = new_state->second;
    if (names.find(state) != names.end()) {
      SE_STEP(true);
      return names[state];
    }
    return std::nullopt;
  }
};

void test_case(std::string str) {
  std::optional<std::string> state = std::nullopt;
  StateMachine machine;
  machine.make_transition(0, 'a', 1);
  machine.make_transition(1, 'b', 2);
  machine.make_transition(2, 'c', 3);
  machine.make_name(3, "final");
  for (char c : str) {
    state = machine.step(c);
    if (!machine.valid) {
      break;
    }
  }
  if (state.has_value()) {
    SE_TARGET_STATE((*state == "final"));
  }
}

int main(int argc, char* argv[]) {
  std::istream* input;
  std::ifstream file;
  if (argc < 2) {
    input = &std::cin; // No file name provided, read from stdin
  } else {
    file.open(argv[1]);
    if (!file) {
      std::cerr << "Could not open the file.\n";
      return 1;
    }
    input = &file; // File opened successfully, read from file
  }
  std::string content(
      (std::istreambuf_iterator<char>(*input)),
      std::istreambuf_iterator<char>());
  test_case(content.c_str());
  return 0;
}