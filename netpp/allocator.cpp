#include "netpp/allocator.h"

namespace netpp {

  StaticBlockAllocator::StaticBlockAllocator(void* buffer, uint32_t block_size, uint32_t block_count) {
    m_buffer = buffer;
    m_block_size = block_size;
    m_block_count = block_count;
    m_block_used.resize(block_count, false);
  }

  StaticBlockAllocator::~StaticBlockAllocator() {
    m_buffer = nullptr;
    m_block_size = 0;
    m_block_count = 0;
  }

  bool StaticBlockAllocator::initialize(void* buffer, uint32_t block_size, uint32_t block_count) {
    if (m_block_count > 0) {
      return false;
    }

    m_buffer = buffer;
    m_block_size = block_size;
    m_block_count = block_count;
    m_block_used.resize(block_count, false);
    return true;
  }

  uint32_t StaticBlockAllocator::allocate() {
    for (uint32_t i = 0; i < m_block_count; i++) {
      if (!m_block_used[i]) {
        m_block_used[i] = true;
        return i;
      }
    }

    return INVALID_BLOCK;
  }

  void StaticBlockAllocator::deallocate(uint32_t block) {
    if (block < m_block_count) {
      m_block_used[block] = false;
    }
  }

  void* StaticBlockAllocator::ptr(uint32_t block) const {
    if (block < m_block_count) {
      return (void*)((char*)m_buffer + (block * m_block_size));
    }

    return nullptr;
  }

  uint32_t StaticBlockAllocator::ofs(uint32_t block) const {
    if (block < m_block_count) {
      return block * m_block_size;
    }

    return INVALID_BLOCK;
  }

  uint32_t StaticBlockAllocator::block(void* ptr) const {
    uint32_t block = (uint32_t)(((uint64_t)ptr - (uint64_t)m_buffer) / m_block_size);
    if (block < m_block_count) {
      return block;
    }

    return INVALID_BLOCK;
  }

}  // namespace netpp
