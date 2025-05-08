#pragma once

#include <cstdint>
#include <vector>

#include "netpp.h"

namespace netpp {

  class StaticBlockAllocator {
  public:
    StaticBlockAllocator() = default;
    StaticBlockAllocator(void* buffer, uint32_t block_size, uint32_t block_count);

    ~StaticBlockAllocator();

    // Invalid block
    static const uint32_t INVALID_BLOCK = -1;

    bool initialize(void* buffer, uint32_t block_size, uint32_t block_count);

    uint32_t allocate();
    void deallocate(uint32_t block);

    uint32_t capacity() const { return m_block_count; }
    uint32_t block_size() const { return m_block_size; }

    void* ptr(uint32_t block) const;
    uint32_t ofs(uint32_t block) const;
    uint32_t block(void* ptr) const;

  private:
    void* m_buffer = nullptr;
    uint32_t m_block_size = 0;
    uint32_t m_block_count = 0;

    std::vector<bool> m_block_used;
  };

}  // namespace netpp