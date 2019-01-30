/*
* Copyright 2018 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#pragma once
#include <string>
#include <vector>

namespace secure
{
template <class T>
class SecureAllocator : public std::allocator<T>
{
public:
  template <class U>
  struct rebind
  {
    typedef SecureAllocator<U> other;
  };

  SecureAllocator() noexcept = default;
  SecureAllocator(const SecureAllocator &) noexcept = default;
  SecureAllocator &operator=(const SecureAllocator &other) = default;
  template <class U>
  SecureAllocator(const SecureAllocator<U> &) noexcept {}

  // atribute for gcc compiler to not optimize out the fill_n
  // if using other compilers than GCC need to check the correct flags
  void __attribute__((optimize("O0"))) deallocate(void *p, size_t n)
  {
    std::fill_n((volatile char *)p, n * sizeof(T), 0);
    std::allocator<T>::deallocate(static_cast<T *>(p), n);
  }
};
using string = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;
template <typename T>
using vector = std::vector<T, SecureAllocator<T>>;

} // namespace secure
