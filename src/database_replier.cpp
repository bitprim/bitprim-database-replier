/**
 * Copyright (c) 2016 Bitprim developers (see AUTHORS)
 *
 * This file is part of Bitprim.
 *
 * Bitprim is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License with
 * additional permissions to the one published by the Free Software
 * Foundation, either version 3 of the License, or (at your option)
 * any later version. For more information see LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

// #include "database_replier.hpp"
#include <bitcoin/database/database_replier.hpp>

#include <memory>
#include <boost/optional.hpp>

#include <bitcoin/protocol/database.pb.h>
#include <bitcoin/protocol/zmq/message.hpp>
#include <bitcoin/protocol/converter.hpp>

//#include <bitcoin/utility/binary.hpp>
#include <bitcoin/bitcoin/utility/binary.hpp>

using namespace libbitcoin::protocol;




namespace libbitcoin { namespace database {


//TODO: Fer: mover de aca a un lugar mas apropiado
std::string pack_hash(hash_digest in) {
    return std::string(in.begin(), in.end());
}

/*

/// Deferred read block result.
class BCD_API block_result
{
public:
    block_result(const memory_ptr slab);
    block_result(const memory_ptr slab, hash_digest&& hash);
    block_result(const memory_ptr slab, const hash_digest& hash);

    /// True if this block result is valid (found).
    operator bool() const;

    /// The block header hash (from cache).
    const hash_digest& hash() const;

    /// The block header.
    chain::header header() const;

    /// The height of this block in the chain.
    size_t height() const;

    /// The header.bits of this block.
    uint32_t bits() const;

    /// The header.timestamp of this block.
    uint32_t timestamp() const;

    /// The header.version of this block.
    uint32_t version() const;

    /// The number of transactions in this block.
    size_t transaction_count() const;

    /// A transaction hash where index < transaction_count.
    hash_digest transaction_hash(size_t index) const;

private:
    const memory_ptr slab_;
    const hash_digest hash_;
};
* 




message block_result {
    bool valid = 1;
    bytes hash = 2;                 // 32-bytes
    block_header header = 3;
    uint32 height = 4;
    uint32 bits = 5;
    uint32 timestamp = 6;
    uint32 version = 7;

    uint32 transaction_count = 8;
    repeated bytes transactions_hashes = 9;
}

*/


//TODO: Fer: mover de aca a un lugar mas apropiado

bool to_protocol(block_result const& blk_result, protocol::block_result& result) {
    
    result.set_allocated_header(converter{}.to_protocol(blk_result.header()));
    if (!result.has_header()) {
        return false;
    }

    auto repeated_transactions_hashes = result.mutable_transactions_hashes();
    
    auto tx_count = blk_result.transaction_count();
    for (size_t i = 0; i < tx_count; ++i) {

        auto tx_hash = blk_result.transaction_hash(i);

        if (!converter{}.to_protocol(tx_hash, *(repeated_transactions_hashes->Add()))) {
            result.clear_header();
            result.clear_transactions_hashes();
            return false;
        }
    }
    
    result.set_valid(blk_result);
    result.set_hash(pack_hash(blk_result.hash()));
    result.set_height(blk_result.height());
    result.set_bits(blk_result.bits());
    result.set_timestamp(blk_result.timestamp());
    result.set_version(blk_result.version());
    result.set_transaction_count(blk_result.transaction_count());
    
    return true;
}

/*
protocol::block_result* converter::to_protocol(block_result const& block) {
    std::unique_ptr<protocol::block> result(new protocol::block());

    if (!to_protocol(block, *(result.get())))
        result.reset();

    return result.release();
}
*/




/*

/// Deferred read transaction result.
class BCD_API transaction_result
{
public:
    transaction_result(const memory_ptr slab);
    transaction_result(const memory_ptr slab, hash_digest&& hash);
    transaction_result(const memory_ptr slab, const hash_digest& hash);

    /// True if this transaction result is valid (found).
    operator bool() const;

    /// The transaction hash (from cache).
    const hash_digest& hash() const;

    /// The height of the block which includes the transaction.
    size_t height() const;

    /// The ordinal position of the transaction within its block.
    size_t position() const;

    /// True if all transaction outputs are spent at or below fork_height.
    bool is_spent(size_t fork_height) const;

    /// The output at the specified index within this transaction.
    chain::output output(uint32_t index) const;

    /// The transaction.
    chain::transaction transaction() const;

private:
    const memory_ptr slab_;
    const hash_digest hash_;
};



message transaction_result {
    bool valid = 1;                 //TODO: Fer: not necessary
    bytes hash = 2;                 // 32-bytes
    uint64 height = 3;
    uint64 position = 4;
    tx transaction = 5;
}

*/



bool to_protocol(transaction_result const& tx_result, protocol::transaction_result& result) {

    auto mutable_transaction = result.mutable_transaction();
    if (!converter{}.to_protocol(tx_result.transaction(), *mutable_transaction)) {
        result.clear_transaction();
        return false;
    }
    
    result.set_valid(tx_result);
    result.set_hash(pack_hash(tx_result.hash()));
    result.set_height(tx_result.height());
    result.set_position(tx_result.position());
    
    return true;
}


/*
enum point_kind {
    point_kind_output = 0;
    point_kind_spend = 1;  
}

 
message history_compact {
    point_kind kind = 1;
    point point = 2;
    uint32 height = 3;
    uint64 value_or_previous_checksum = 4;
}
}


/home/fernando/dev/112bit/database-replier/bitprim-database/src/database_replier.cpp:500:60: 
* error: no matching function for call to ‘to_protocol(const libbitcoin::chain::history_compact&, libbitcoin::protocol::history_compact&)’
         to_protocol(hist_compact, *(repeated_result->Add()));



*/


bool to_protocol(chain::history_compact const& h_compact, protocol::history_compact& result) {

    auto mutable_point = result.mutable_point();
    if (!converter{}.to_protocol(h_compact.point, *mutable_point)) {
        result.clear_point();
        return false;
    }
    
    
    
    result.set_kind(protocol::point_kind(h_compact.kind));
    result.set_height(h_compact.height);
    result.set_value_or_previous_checksum(h_compact.value);
    //result.set_value_or_previous_checksum(h_compact.previous_checksum);
    
    return true;
}


/*
message binary {
    bytes blocks = 1;
    uint32 final_block_excess = 2; //uint8 not supported by Protobuf
}
*/


bool from_protocol(protocol::binary const* binary, libbitcoin::binary& result) {
    if (binary == nullptr)
        return false;

    const auto blocks_text = binary->blocks();
    const data_chunk data(blocks_text.begin(), blocks_text.end());

    //binary::binary(size_type size, data_slice blocks)
    result = libbitcoin::binary(data.size(), data);
    
    return true;
}



/*
message stealth_compact {
    bytes ephemeral_public_key_hash = 1;
    bytes public_key_hash = 2;
    bytes transaction_hash = 3;
}
*/



bool to_protocol(chain::stealth_compact const& s_compact, protocol::stealth_compact& result) {
    
    result.set_ephemeral_public_key_hash(pack_hash(s_compact.ephemeral_public_key_hash));
    
    result.set_transaction_hash(pack_hash(s_compact.transaction_hash));

    //result.set_public_key_hash(pack_hash(s_compact.public_key_hash));
    //converter{}.to_protocol(s_compact.public_key_hash, std::string& result)
    
    auto mutable_public_key_hash = result.mutable_public_key_hash();
    if (!converter{}.to_protocol(s_compact.public_key_hash, *mutable_public_key_hash)) {
        result.clear_public_key_hash();
        return false;
    }
    
    return true;
}


// ----------------------------------------------------------------

/*

bool from_protocol(protocol::binary const* binary, libbitcoin::binary& result) {
    if (binary == nullptr)
        return false;

    const auto blocks_text = binary->blocks();
    const data_chunk data(blocks_text.begin(), blocks_text.end());

    //binary::binary(size_type size, data_slice blocks)
    result = libbitcoin::binary(data.size(), data);
    
    return true;
}

bool from_protocol(protocol::block_result const* blk_result, block_result& result) {

    bool valid_;
    const hash_digest hash_;
    chain::header header_;
    std::vector<hash_digest> tx_hashes_;
    
    
    result.set_valid(blk_result->valid());
    
    if (blk_result->valid()) {
    
        hash_digest hash;
        converter{}.from_protocol(blk_result->hash(), hash);
        result.set_hash(hash);
        
        chain::header header;
        converter{}.from_protocol(blk_result->header(), header);
        result.set_header(header);

        std::vector<hash_digest> tx_hashes;

        for (auto const& tx_hash : blk_result->transactions_hashes()) {
            converter{}.from_protocol(tx_hash, hash);
            tx_hashes.push_back(hash);
        }
        result.set_transaction_hashes(tx_hashes);
    }

    return true;
}
*/
// ----------------------------------------------------------------






boost::optional<data_base> data_base_;

//! bool block_database::top(size_t& out_height) const;
static protocol::database::top_reply dispatch_top(
    const protocol::database::top_request& request) {

    BITCOIN_ASSERT(data_base_);
    
    std::cout << "dispatch_top - 1\n";

    size_t out_height;
    bool const result = data_base_->blocks().top(out_height);

    std::cout << "dispatch_top - 2\n";


    protocol::database::top_reply reply;
    reply.set_out_height(out_height);
    reply.set_result(result);
    
    std::cout << "dispatch_top - 3\n";

    return reply;
}

//! block_result block_database::get(size_t height) const
static protocol::database::get_reply dispatch_get(
    const protocol::database::get_request& request) {

    BITCOIN_ASSERT(data_base_);

    size_t height = request.height();
    block_result const result = data_base_->blocks().get(height);

    protocol::database::get_reply reply;
    to_protocol(result, *reply.mutable_result());

    return reply;
}

//! block_result block_database::get(const hash_digest& hash) const
static protocol::database::get_by_hash_reply dispatch_get_by_hash(
    const protocol::database::get_by_hash_request& request) {

    BITCOIN_ASSERT(data_base_);
   
    hash_digest hash;
    converter{}.from_protocol(&request.hash(), hash);
    block_result const result = data_base_->blocks().get(hash);

    protocol::database::get_by_hash_reply reply;
    to_protocol(result, *reply.mutable_result());

    return reply;
}

//! bool block_database::gaps(heights& out_gaps) const
static protocol::database::gaps_reply dispatch_gaps(
    const protocol::database::gaps_request& request) {

    BITCOIN_ASSERT(data_base_);

    block_database::heights out_gaps;
    bool const result = data_base_->blocks().gaps(out_gaps);

    protocol::database::gaps_reply reply;
    reply.set_result(result);
    
    
    //converter{}.to_protocol(out_gaps, *reply.mutable_out_gaps());      //TODO: Fer: implement to_protocol() for block_database::heights aka std::vector<unsigned long>
    //auto repeated_out_gaps = result.mutable_out_gaps();
    
    for (auto const& gap : out_gaps) {
        reply.add_out_gaps(gap);
    }

    return reply;
}





//! bool data_base::insert(const chain::block& block, size_t height)
static protocol::database::insert_block_reply dispatch_insert_block(
    const protocol::database::insert_block_request& request) {

    BITCOIN_ASSERT(data_base_);

    size_t height = request.height();
    chain::block block;
    //PARSE BLOCK FROM MESSAGE
    
    //TODO CHECK IF SUCCESFULL
    protocol::converter converter;
    converter.from_protocol(&(request.blockr()), block);

    bool const result = data_base_->insert(block, height);

    protocol::database::insert_block_reply reply;
    reply.set_result(result);
    return reply;
}

//! bool data_base::push(const block& block, size_t height)
static protocol::database::push_reply dispatch_push(
    const protocol::database::push_request& request) {

    BITCOIN_ASSERT(data_base_);

    size_t height = request.height();
    
    chain::block block;
    converter{}.from_protocol(&request.block(), block);
    //TODO CHECK IF SUCCESFULL

    bool const result = data_base_->push(block, height);

    protocol::database::push_reply reply;
    reply.set_result(result);
    return reply;
}

//! bool data_base::pop_above(block::list& out_blocks, const hash_digest& fork_hash)
static protocol::database::pop_above_reply dispatch_pop_above(
    const protocol::database::pop_above_request& request) {

    BITCOIN_ASSERT(data_base_);

    hash_digest fork_hash;
    converter{}.from_protocol(&request.fork_hash(), fork_hash);

    chain::block::list out_blocks;
    bool const result = data_base_->pop_above(out_blocks, fork_hash);

    protocol::database::pop_above_reply reply;
    reply.set_result(result);
    //converter{}.to_protocol(out_blocks, *reply.mutable_out_blocks());      //TODO: Fer: implement to_protocol() for chain::block::list

    auto repeated_out_blocks = reply.mutable_out_blocks();

    for (auto const& out_block : out_blocks) {
        converter{}.to_protocol(out_block, *(repeated_out_blocks->Add()));
    }

    return reply;
}


//! bool store::flush_lock()
static protocol::database::flush_lock_reply dispatch_flush_lock(
    const protocol::database::flush_lock_request& request) {

    BITCOIN_ASSERT(data_base_);

    bool const result = data_base_->flush_lock();

    protocol::database::flush_lock_reply reply;
    reply.set_result(result);
    return reply;
}

//! bool store::flush_unlock()
static protocol::database::flush_unlock_reply dispatch_flush_unlock(
    const protocol::database::flush_unlock_request& request) {

    BITCOIN_ASSERT(data_base_);

    bool const result = data_base_->flush_unlock();

    protocol::database::flush_unlock_reply reply;
    reply.set_result(result);
    return reply;
}

//! store::handle store::begin_read() const
static protocol::database::begin_read_reply dispatch_begin_read(
    const protocol::database::begin_read_request& request) {

    BITCOIN_ASSERT(data_base_);

    size_t const result = data_base_->begin_read();

    protocol::database::begin_read_reply reply;
    reply.set_result(result);
    return reply;
}

//! bool store::begin_write(bool lock)
static protocol::database::begin_write_reply dispatch_begin_write(
    const protocol::database::begin_write_request& request) {

    BITCOIN_ASSERT(data_base_);

    bool lock = request.lock();
    bool const result = data_base_->begin_write(lock);

    protocol::database::begin_write_reply reply;
    reply.set_result(result);
    return reply;
}

//! bool store::end_write(bool unlock)
static protocol::database::end_write_reply dispatch_end_write(
    const protocol::database::end_write_request& request) {

    BITCOIN_ASSERT(data_base_);

    bool unlock = request.unlock();
    bool const result = data_base_->end_write(unlock);

    protocol::database::end_write_reply reply;
    reply.set_result(result);
    return reply;
}

//! bool store::is_write_locked(handle value) const
static protocol::database::is_write_locked_reply dispatch_is_write_locked(
    const protocol::database::is_write_locked_request& request) {

    BITCOIN_ASSERT(data_base_);

    size_t handle = request.handle();
    bool const result = data_base_->is_write_locked(handle);

    protocol::database::is_write_locked_reply reply;
    reply.set_result(result);
    return reply;
}

//! bool store::is_read_valid(handle value) const
static protocol::database::is_read_valid_reply dispatch_is_read_valid(
    const protocol::database::is_read_valid_request& request) {

    BITCOIN_ASSERT(data_base_);

    size_t handle = request.handle();
    bool const result = data_base_->is_read_valid(handle);

    protocol::database::is_read_valid_reply reply;
    reply.set_result(result);
    return reply;
}

//! transaction_result transaction_database::get(const hash_digest& hash) const
static protocol::database::get_transaction_reply dispatch_get_transaction(
    const protocol::database::get_transaction_request& request) {

    BITCOIN_ASSERT(data_base_);
   
    hash_digest hash;
    converter{}.from_protocol(&request.hash(), hash);
    transaction_result const result = data_base_->transactions().get(hash);

    protocol::database::get_transaction_reply reply;
    to_protocol(result, *reply.mutable_result());      //TODO: Fer: implement to_protocol() for transaction_result

    return reply;
}



//! history_compact::list history_database::get(const short_hash& key, size_t limit, size_t from_height) const
static protocol::database::get_history_database_reply dispatch_get_history_database(
    const protocol::database::get_history_database_request& request) {

    BITCOIN_ASSERT(data_base_);
   
    short_hash key;
    converter{}.from_protocol(&request.key(), key);
    chain::history_compact::list const result = data_base_->history().get(key, request.limit(), request.from_height());

    protocol::database::get_history_database_reply reply;
    //converter{}.to_protocol(result, *reply.mutable_result());      //TODO: Fer: implement to_protocol() for history_compact::list
    
    auto repeated_result = reply.mutable_result();

    for (auto const& hist_compact : result) {
        to_protocol(hist_compact, *(repeated_result->Add()));
    }

    return reply;
}




//! stealth_compact::list stealth_database::scan(const binary& filter, size_t from_height) const
static protocol::database::stealth_database_scan_reply dispatch_stealth_database_scan(
    const protocol::database::stealth_database_scan_request& request) {

    BITCOIN_ASSERT(data_base_);
   
    binary filter;
    from_protocol(&request.filter(), filter);
    chain::stealth_compact::list const result = data_base_->stealth().scan(filter, request.from_height());

    protocol::database::stealth_database_scan_reply reply;
    //to_protocol(result, *reply.mutable_result());      //TODO: Fer: implement to_protocol() for chain::stealth_compact::list
    
    
    auto repeated_result = reply.mutable_result();

    for (auto const& s_compact : result) {
        to_protocol(s_compact, *(repeated_result->Add()));
    }
    

    return reply;
}





//!
zmq::message dispatch(
    const protocol::database::request& request)
{
    zmq::message reply;
    switch (request.request_type_case()) {
        case protocol::database::request::kTop: {
            reply.enqueue_protobuf_message(
                dispatch_top(request.top()));
            break;
        }
        case protocol::database::request::kGet: {
            reply.enqueue_protobuf_message(
                dispatch_get(request.get()));
            break;
        }
        case protocol::database::request::kGetByHash: {
            reply.enqueue_protobuf_message(
                dispatch_get_by_hash(request.get_by_hash()));
            break;
        }
        case protocol::database::request::kGaps: {
            reply.enqueue_protobuf_message(
                dispatch_gaps(request.gaps()));
            break;
        }
        
        
        case protocol::database::request::kInsertBlock: {
            reply.enqueue_protobuf_message(
                dispatch_insert_block(request.insert_block()));
            break;
        }
        case protocol::database::request::kPush: {
            reply.enqueue_protobuf_message(
                dispatch_push(request.push()));
            break;
        }
        case protocol::database::request::kPopAbove: {
            reply.enqueue_protobuf_message(
                dispatch_pop_above(request.pop_above()));
            break;
        }
        
        
        
        
        case protocol::database::request::kFlushLock: {
            reply.enqueue_protobuf_message(
                dispatch_flush_lock(request.flush_lock()));
            break;
        }
        case protocol::database::request::kFlushUnlock: {
            reply.enqueue_protobuf_message(
                dispatch_flush_unlock(request.flush_unlock()));
            break;
        }
        case protocol::database::request::kBeginRead: {
            reply.enqueue_protobuf_message(
                dispatch_begin_read(request.begin_read()));
            break;
        }
        case protocol::database::request::kBeginWrite: {
            reply.enqueue_protobuf_message(
                dispatch_begin_write(request.begin_write()));
            break;
        }
        case protocol::database::request::kEndWrite: {
            reply.enqueue_protobuf_message(
                dispatch_end_write(request.end_write()));
            break;
        }
        case protocol::database::request::kIsWriteLocked: {
            reply.enqueue_protobuf_message(
                dispatch_is_write_locked(request.is_write_locked()));
            break;
        }
        case protocol::database::request::kIsReadValid: {
            reply.enqueue_protobuf_message(
                dispatch_is_read_valid(request.is_read_valid()));
            break;
        }
        case protocol::database::request::kGetTransaction: {
            reply.enqueue_protobuf_message(
                dispatch_get_transaction(request.get_transaction()));
            break;
        }
        case protocol::database::request::kGetHistoryDatabase: {
            reply.enqueue_protobuf_message(
                dispatch_get_history_database(request.get_history_database()));
            break;
        }
        case protocol::database::request::kStealthDatabaseScan: {
            reply.enqueue_protobuf_message(
                dispatch_stealth_database_scan(request.stealth_database_scan()));
            break;
        }
        
        

    }
    return reply;
}




//--------------------------------------------------------------------------

// //! bool block_chain_impl::start();
// static protocol::blockchain::start_reply dispatch_start(
//     const protocol::blockchain::start_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     const bool result = block_database_->start();

//     protocol::blockchain::start_reply reply;
//     reply.set_result(result);
//     return reply;
// }

// //! bool block_chain_impl::stop();
// static protocol::blockchain::stop_reply dispatch_stop(
//     const protocol::blockchain::stop_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     const bool result = block_database_->stop();

//     protocol::blockchain::stop_reply reply;
//     reply.set_result(result);
//     return reply;
// }

// //! bool block_chain_impl::close();
// static protocol::blockchain::close_reply dispatch_close(
//     const protocol::blockchain::close_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     const bool result = block_database_->close();

//     protocol::blockchain::close_reply reply;
//     reply.set_result(result);
//     return reply;
// }

// //! bool block_chain_impl::get_gap_range(uint64_t& out_first, uint64_t& out_last) const;
// static protocol::blockchain::get_gap_range_reply dispatch_get_gap_range(
//     const protocol::blockchain::get_gap_range_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     uint64_t out_first, out_last;
//     const bool result = block_database_->get_gap_range(out_first, out_last);

//     protocol::blockchain::get_gap_range_reply reply;
//     reply.set_result(result);
//     if (result)
//     {
//         reply.set_out_first(out_first);
//         reply.set_out_last(out_last);
//     }
//     return reply;
// }

// //! bool block_chain_impl::get_next_gap(uint64_t& out_height, uint64_t start_height) const;
// static protocol::blockchain::get_next_gap_reply dispatch_get_next_gap(
//     const protocol::blockchain::get_next_gap_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     uint64_t out_height;
//     const uint64_t start_height = request.start_height();
//     const bool result = block_database_->get_next_gap(out_height, start_height);

//     protocol::blockchain::get_next_gap_reply reply;
//     reply.set_result(result);
//     if (result)
//     {
//         reply.set_out_height(out_height);
//     }
//     return reply;
// }

// //! bool block_chain_impl::get_difficulty(hash_number& out_difficulty, uint64_t height) const;
// static protocol::blockchain::get_difficulty_reply dispatch_get_difficulty(
//     const protocol::blockchain::get_difficulty_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     hash_number out_difficulty;
//     const uint64_t height = request.height();
//     const bool result = block_database_->get_difficulty(out_difficulty, height);

//     protocol::blockchain::get_difficulty_reply reply;
//     reply.set_result(result);
//     if (result)
//     {
//         hash_digest hash = out_difficulty.hash();
//         converter{}.to_protocol(hash, *reply.mutable_out_difficulty());
//     }
//     return reply;
// }

// //! bool block_chain_impl::get_header(chain::header& out_header, uint64_t height) const;
// static protocol::blockchain::get_header_reply dispatch_get_header(
//     const protocol::blockchain::get_header_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     chain::header out_header;
//     const uint64_t height = request.height();
//     const bool result = block_database_->get_header(out_header, height);

//     protocol::blockchain::get_header_reply reply;
//     reply.set_result(result);
//     if (result)
//     {
//         converter{}.to_protocol(out_header, *reply.mutable_out_header());
//     }
//     return reply;
// }

// //! bool block_chain_impl::get_height(uint64_t& out_height, const hash_digest& block_hash) const;
// static protocol::blockchain::get_height_reply dispatch_get_height(
//     const protocol::blockchain::get_height_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     uint64_t out_height;
//     hash_digest block_hash;
//     converter{}.from_protocol(&request.block_hash(), block_hash);
//     const bool result = block_database_->get_height(out_height, block_hash);

//     protocol::blockchain::get_height_reply reply;
//     reply.set_result(result);
//     if (result)
//     {
//         reply.set_out_height(out_height);
//     }
//     return reply;
// }

// //! bool block_chain_impl::get_last_height(uint64_t& out_height) const;
// static protocol::blockchain::get_last_height_reply dispatch_get_last_height(
//     const protocol::blockchain::get_last_height_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     uint64_t out_height;
//     const bool result = block_database_->get_last_height(out_height);

//     protocol::blockchain::get_last_height_reply reply;
//     reply.set_result(result);
//     if (result)
//     {
//         reply.set_out_height(out_height);
//     }
//     return reply;
// }


// //! bool block_chain_impl::get_outpoint_transaction(hash_digest& out_transaction_hash,
// //!     const chain::output_point& outpoint) const;
// static protocol::blockchain::get_outpoint_transaction_reply dispatch_get_outpoint_transaction(
//     const protocol::blockchain::get_outpoint_transaction_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     hash_digest out_transaction_hash;
//     chain::output_point outpoint;
//     converter{}.from_protocol(&request.outpoint(), outpoint);
//     const bool result = block_database_->get_outpoint_transaction(out_transaction_hash, outpoint);

//     protocol::blockchain::get_outpoint_transaction_reply reply;
//     reply.set_result(result);
//     if (result)
//     {
//         converter{}.to_protocol(out_transaction_hash, *reply.mutable_out_transaction_hash());
//     }
//     return reply;
// }


// //! bool block_chain_impl::get_transaction(chain::transaction& out_transaction,
// //!     uint64_t& out_block_height, const hash_digest& transaction_hash) const;
// static protocol::blockchain::get_transaction_reply dispatch_get_transaction(
//     const protocol::blockchain::get_transaction_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     chain::transaction out_transaction;
//     uint64_t out_block_height;
//     hash_digest transaction_hash;
//     converter{}.from_protocol(&request.transaction_hash(), transaction_hash);
//     const bool result = block_database_->get_transaction(out_transaction, out_block_height, transaction_hash);

//     protocol::blockchain::get_transaction_reply reply;
//     reply.set_result(result);
//     if (result)
//     {
//         converter{}.to_protocol(out_transaction, *reply.mutable_out_transaction());
//         reply.set_out_block_height(out_block_height);
//     }
//     return reply;
// }

// //! bool block_chain_impl::get_transaction_height(uint64_t& out_block_height,
// //!     const hash_digest& transaction_hash) const;
// static protocol::blockchain::get_transaction_height_reply dispatch_get_transaction_height(
//     const protocol::blockchain::get_transaction_height_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     uint64_t out_block_height;
//     hash_digest transaction_hash;
//     converter{}.from_protocol(&request.transaction_hash(), transaction_hash);
//     const bool result = block_database_->get_transaction_height(out_block_height, transaction_hash);

//     protocol::blockchain::get_transaction_height_reply reply;
//     reply.set_result(result);
//     if (result)
//     {
//         reply.set_out_block_height(out_block_height);
//     }
//     return reply;
// }

// //! bool block_chain_impl::import(chain::block::ptr block, uint64_t height);
// static protocol::blockchain::import_reply dispatch_import(
//     const protocol::blockchain::import_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     chain::block actual;
//     converter{}.from_protocol(&request.block(), actual);
//     chain::block::ptr const block = std::make_shared<chain::block>(std::move(actual));
//     uint64_t const height = request.height();
//     const bool result = block_database_->import(block, height);

//     protocol::blockchain::import_reply reply;
//     reply.set_result(result);

//     return reply;
// }

// //! bool block_chain_impl::push(block_detail::ptr block);
// static protocol::blockchain::push_reply dispatch_push(
//     const protocol::blockchain::push_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     chain::block actual;
//     converter{}.from_protocol(&request.block().actual(), actual);
//     block_detail::ptr const block = std::make_shared<block_detail>(std::move(actual));
//     block->actual()->set_originator(request.block().originator());
//     block->set_error(error::error_code_t(request.block().error()));
//     if (request.block().processed())
//         block->set_processed();
//     block->set_height(request.block().height());
//     const bool result = block_database_->push(block);

//     protocol::blockchain::push_reply reply;
//     reply.set_result(result);

//     return reply;
// }

// //! bool block_chain_impl::pop_from(block_detail::list& out_blocks, uint64_t height);
// static protocol::blockchain::pop_from_reply dispatch_pop_from(
//     const protocol::blockchain::pop_from_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     block_detail::list out_blocks;
//     uint64_t const height = request.height();
//     const bool result = block_database_->pop_from(out_blocks, height);

//     protocol::blockchain::pop_from_reply reply;
//     reply.set_result(result);
//     if (result)
//     {
//         for (auto const& out_block : out_blocks)
//         {
//             auto* new_block = reply.add_out_blocks();
//             converter{}.to_protocol(*out_block->actual(), *new_block->mutable_actual());
//             new_block->set_originator(out_block->actual()->originator());
//             new_block->set_error(out_block->error().value());
//             new_block->set_processed(out_block->processed());
//             new_block->set_height(out_block->height());
//         }
//     }
//     return reply;
// }

// //! void block_chain_impl::store(message::block_message::ptr block,
// //!     block_store_handler handler);
// static protocol::void_reply dispatch_store(
//     const protocol::blockchain::store_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     chain::block actual;
//     converter{}.from_protocol(&request.actual(), actual);
//     message::block_message::ptr const block =
//         std::make_shared<message::block_message>(std::move(actual));
//     block->set_originator(request.originator());
//     block_database_->store(block,
//         replier_.make_handler<protocol::blockchain::store_handler>(
//             request.handler(),
//             [] (const code& error, uint64_t height,
//                 protocol::blockchain::store_handler& handler) -> void
//             {
//                 handler.set_error(error.value());
//                 handler.set_height(height);
//             }));

//     protocol::void_reply reply;
//     return reply;
// }

// //! void block_chain_impl::fetch_block(uint64_t height, block_fetch_handler handler);
// //! void block_chain_impl::fetch_block(const hash_digest& hash, block_fetch_handler handler);
// static protocol::void_reply dispatch_fetch_block(
//     const protocol::blockchain::fetch_block_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     auto const& handler =
//         replier_.make_handler<protocol::blockchain::fetch_block_handler>(
//             request.handler(),
//             [] (const code& error, chain::block::ptr block,
//                 protocol::blockchain::fetch_block_handler& handler) -> void
//             {
//                 handler.set_error(error.value());
//                 if (block)
//                 {
//                     converter{}.to_protocol(*block, *handler.mutable_block());
//                 }
//             });
//     if (request.hash().empty())
//     {
//         uint64_t height = request.height();
//         block_database_->fetch_block(height, handler);
//     } else {
//         hash_digest hash;
//         converter{}.from_protocol(&request.hash(), hash);
//         block_database_->fetch_block(hash, handler);
//     }

//     protocol::void_reply reply;
//     return reply;
// }

// //! void block_chain_impl::fetch_block_header(uint64_t height,
// //!     block_header_fetch_handler handler);
// //! void block_chain_impl::fetch_block_header(const hash_digest& hash,
// //!     block_header_fetch_handler handler);
// static protocol::void_reply dispatch_fetch_block_header(
//     const protocol::blockchain::fetch_block_header_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     auto const& handler =
//         replier_.make_handler<protocol::blockchain::fetch_block_header_handler>(
//             request.handler(),
//             [] (const code& error, chain::header const& header,
//                 protocol::blockchain::fetch_block_header_handler& handler) -> void
//             {
//                 handler.set_error(error.value());
//                 converter{}.to_protocol(header, *handler.mutable_header());
//             });
//     if (request.hash().empty())
//     {
//         uint64_t height = request.height();
//         block_database_->fetch_block_header(height, handler);
//     } else {
//         hash_digest hash;
//         converter{}.from_protocol(&request.hash(), hash);
//         block_database_->fetch_block_header(hash, handler);
//     }

//     protocol::void_reply reply;
//     return reply;
// }

// //! void block_chain_impl::fetch_merkle_block(uint64_t height,
// //!     merkle_block_fetch_handler handler);
// //! void block_chain_impl::fetch_merkle_block(const hash_digest& hash,
// //!     merkle_block_fetch_handler handler);
// static protocol::void_reply dispatch_fetch_merkle_block(
//     const protocol::blockchain::fetch_merkle_block_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     auto const& handler =
//         replier_.make_handler<protocol::blockchain::fetch_merkle_block_handler>(
//             request.handler(),
//             [] (const code& error, message::merkle_block::ptr block,
//                 protocol::blockchain::fetch_merkle_block_handler& handler) -> void
//             {
//                 handler.set_error(error.value());
//                 if (block)
//                 {
//                     auto* merkle_block = handler.mutable_block();
//                     converter{}.to_protocol(block->header, *merkle_block->mutable_header());
//                     for (auto const& entry : block->hashes)
//                     {
//                         converter{}.to_protocol(entry, *merkle_block->add_hashes());
//                     }
//                     merkle_block->set_flags(block->flags.data(), block->flags.size());
//                 }
//             });
//     if (request.hash().empty())
//     {
//         uint64_t height = request.height();
//         block_database_->fetch_merkle_block(height, handler);
//     } else {
//         hash_digest hash;
//         converter{}.from_protocol(&request.hash(), hash);
//         block_database_->fetch_merkle_block(hash, handler);
//     }

//     protocol::void_reply reply;
//     return reply;
// }

// //! void block_chain_impl::fetch_block_transaction_hashes(uint64_t height,
// //!     transaction_hashes_fetch_handler handler);
// //! void block_chain_impl::fetch_block_transaction_hashes(const hash_digest& hash,
// //!     transaction_hashes_fetch_handler handler);
// static protocol::void_reply dispatch_fetch_block_transaction_hashes(
//     const protocol::blockchain::fetch_block_transaction_hashes_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     auto const& handler =
//         replier_.make_handler<protocol::blockchain::fetch_block_transaction_hashes_handler>(
//             request.handler(),
//             [] (const code& error, hash_list const& hashes,
//                 protocol::blockchain::fetch_block_transaction_hashes_handler& handler) -> void
//             {
//                 handler.set_error(error.value());
//                 for (auto const& entry : hashes)
//                 {
//                     converter{}.to_protocol(entry, *handler.add_hashes());
//                 }
//             });
//     if (request.hash().empty())
//     {
//         uint64_t height = request.height();
//         block_database_->fetch_block_transaction_hashes(height, handler);
//     } else {
//         hash_digest hash;
//         converter{}.from_protocol(&request.hash(), hash);
//         block_database_->fetch_block_transaction_hashes(hash, handler);
//     }

//     protocol::void_reply reply;
//     return reply;
// }

// //! void block_chain_impl::fetch_block_locator(block_locator_fetch_handler handler);
// static protocol::void_reply dispatch_fetch_block_locator(
//     const protocol::blockchain::fetch_block_locator_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     block_database_->fetch_block_locator(
//         replier_.make_handler<protocol::blockchain::fetch_block_locator_handler>(
//             request.handler(),
//             [] (const code& error, hash_list const& locator,
//                 protocol::blockchain::fetch_block_locator_handler& handler) -> void
//             {
//                 handler.set_error(error.value());
//                 for (auto const& entry : locator)
//                 {
//                     converter{}.to_protocol(entry, *handler.add_locator());
//                 }
//             }));

//     protocol::void_reply reply;
//     return reply;
// }

// //! void block_chain_impl::fetch_locator_block_hashes(const message::get_blocks& locator,
// //!     const hash_digest& threshold, size_t limit,
// //!     locator_block_hashes_fetch_handler handler);
// static protocol::void_reply dispatch_fetch_locator_block_hashes(
//     const protocol::blockchain::fetch_locator_block_hashes_request& request)
// {
//     BITCOIN_ASSERT(block_database_);
//     message::get_blocks locator;
//     locator.start_hashes.reserve(request.locator().start_hashes_size());
//     for (auto const& entry : request.locator().start_hashes())
//     {
//         hash_digest hash;
//         converter{}.from_protocol(&entry, hash);

//         locator.start_hashes.push_back(std::move(hash));
//     }
//     converter{}.from_protocol(&request.locator().stop_hash(), locator.stop_hash);
//     hash_digest threshold;
//     converter{}.from_protocol(&request.threshold(), threshold);
//     const size_t limit = request.limit();
//     block_database_->fetch_locator_block_hashes(locator, threshold, limit,
//         replier_.make_handler<protocol::blockchain::fetch_locator_block_hashes_handler>(
//             request.handler(),
//             [] (const code& error, hash_list const& hashes,
//                 protocol::blockchain::fetch_locator_block_hashes_handler& handler) -> void
//             {
//                 handler.set_error(error.value());
//                 for (auto const& entry : hashes)
//                 {
//                     converter{}.to_protocol(entry, *handler.add_hashes());
//                 }
//             }));

//     protocol::void_reply reply;
//     return reply;
// }

// //! void block_chain_impl::fetch_locator_block_headers(const message::get_headers& locator,
// //!     const hash_digest& threshold, size_t limit,
// //!     locator_block_headers_fetch_handler handler);
// static protocol::void_reply dispatch_fetch_locator_block_headers(
//     const protocol::blockchain::fetch_locator_block_headers_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     message::get_headers locator;
//     locator.start_hashes.reserve(request.locator().start_hashes_size());
//     for (auto const& entry : request.locator().start_hashes())
//     {
//         hash_digest hash;
//         converter{}.from_protocol(&entry, hash);

//         locator.start_hashes.push_back(std::move(hash));
//     }
//     converter{}.from_protocol(&request.locator().stop_hash(), locator.stop_hash);
//     hash_digest threshold;
//     converter{}.from_protocol(&request.threshold(), threshold);
//     const size_t limit = request.limit();
//     block_database_->fetch_locator_block_headers(locator, threshold, limit,
//         replier_.make_handler<protocol::blockchain::fetch_locator_block_headers_handler>(
//             request.handler(),
//             [] (const code& error, chain::header::list const& headers,
//                 protocol::blockchain::fetch_locator_block_headers_handler& handler) -> void
//             {
//                 handler.set_error(error.value());
//                 for (auto const& entry : headers)
//                 {
//                     converter{}.to_protocol(entry, *handler.add_headers());
//                 }
//             }));

//     protocol::void_reply reply;
//     return reply;
// }

// //! void block_chain_impl::fetch_block_height(const hash_digest& hash,
// //!     block_height_fetch_handler handler);
// static protocol::void_reply dispatch_fetch_block_height(
//     const protocol::blockchain::fetch_block_height_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     hash_digest hash;
//     converter{}.from_protocol(&request.hash(), hash);
//     block_database_->fetch_block_height(hash,
//         replier_.make_handler<protocol::blockchain::fetch_block_height_handler>(
//             request.handler(),
//             [] (const code& error, uint64_t height,
//                 protocol::blockchain::fetch_block_height_handler& handler) -> void
//             {
//                 handler.set_error(error.value());
//                 handler.set_height(height);
//             }));

//     protocol::void_reply reply;
//     return reply;
// }

// //! void block_chain_impl::fetch_last_height(last_height_fetch_handler handler);
// static protocol::void_reply dispatch_fetch_last_height(
//     const protocol::blockchain::fetch_last_height_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     block_database_->fetch_last_height(
//         replier_.make_handler<protocol::blockchain::fetch_last_height_handler>(
//             request.handler(),
//             [] (const code& error, uint64_t height,
//                 protocol::blockchain::fetch_last_height_handler& handler) -> void
//             {
//                 handler.set_error(error.value());
//                 handler.set_height(height);
//             }));

//     protocol::void_reply reply;
//     return reply;
// }

// //! void block_chain_impl::fetch_transaction(const hash_digest& hash,
// //!     transaction_fetch_handler handler);
// static protocol::void_reply dispatch_fetch_transaction(
//     const protocol::blockchain::fetch_transaction_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     hash_digest hash;
//     converter{}.from_protocol(&request.hash(), hash);
//     block_database_->fetch_transaction(hash,
//         replier_.make_handler<protocol::blockchain::fetch_transaction_handler>(
//             request.handler(),
//             [] (const code& error, chain::transaction const& tx,
//                 protocol::blockchain::fetch_transaction_handler& handler) -> void
//             {
//                 handler.set_error(error.value());
//                 converter{}.to_protocol(tx, *handler.mutable_transaction());
//             }));

//     protocol::void_reply reply;
//     return reply;
// }

// //! void block_chain_impl::fetch_transaction_index(const hash_digest& hash,
// //!     transaction_index_fetch_handler handler);
// static protocol::void_reply dispatch_fetch_transaction_index(
//     const protocol::blockchain::fetch_transaction_index_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     hash_digest hash;
//     converter{}.from_protocol(&request.hash(), hash);
//     block_database_->fetch_transaction_index(hash,
//         replier_.make_handler<protocol::blockchain::fetch_transaction_index_handler>(
//             request.handler(),
//             [] (const code& error, uint64_t height, uint64_t index,
//                 protocol::blockchain::fetch_transaction_index_handler& handler) -> void
//             {
//                 handler.set_error(error.value());
//                 handler.set_height(height);
//                 handler.set_index(index);
//             }));

//     protocol::void_reply reply;
//     return reply;
// }

// //! void block_chain_impl::fetch_spend(const chain::output_point& outpoint,
// //!     spend_fetch_handler handler);
// static protocol::void_reply dispatch_fetch_spend(
//     const protocol::blockchain::fetch_spend_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     chain::output_point outpoint;
//     converter{}.from_protocol(&request.outpoint(), outpoint);
//     block_database_->fetch_spend(outpoint,
//         replier_.make_handler<protocol::blockchain::fetch_spend_handler>(
//             request.handler(),
//             [] (const code& error, chain::input_point const& point,
//                 protocol::blockchain::fetch_spend_handler& handler) -> void
//             {
//                 handler.set_error(error.value());
//                 converter{}.to_protocol(point, *handler.mutable_point());
//             }));

//     protocol::void_reply reply;
//     return reply;
// }

// //! void block_chain_impl::fetch_history(const wallet::payment_address& address,
// //!     uint64_t limit, uint64_t from_height, history_fetch_handler handler);
// static protocol::void_reply dispatch_fetch_history(
//     const protocol::blockchain::fetch_history_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     wallet::payment_address address;
//     if (request.address().valid())
//     {
//         const uint8_t version = request.address().version();
//         short_hash hash;
//         converter{}.from_protocol(&request.address().hash(), hash);
//         address = { hash, version };
//     }
//     const uint64_t limit = request.limit();
//     const uint64_t from_height = request.from_height();
//     block_database_->fetch_history(address, limit, from_height,
//         replier_.make_handler<protocol::blockchain::fetch_history_handler>(
//             request.handler(),
//             [] (const code& error, chain::history_compact::list const& history,
//                 protocol::blockchain::fetch_history_handler& handler) -> void
//             {
//                 handler.set_error(error.value());
//                 for (auto const& entry : history)
//                 {
//                     auto* history_compact = handler.add_history();
//                     history_compact->set_kind(static_cast<int>(entry.kind));
//                     converter{}.to_protocol(entry.point, *history_compact->mutable_point());
//                     history_compact->set_height(entry.height);
//                     history_compact->set_value(entry.value);
//                 }
//             }));

//     protocol::void_reply reply;
//     return reply;
// }

// //! void block_chain_impl::fetch_stealth(const binary& filter, uint64_t from_height,
// //!     stealth_fetch_handler handler);
// static protocol::void_reply dispatch_fetch_stealth(
//     const protocol::blockchain::fetch_stealth_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     const uint64_t filter_size = request.filter_size();
//     const auto& filter_blocks = request.filter_blocks();
//     const data_slice filter_slice(
//         reinterpret_cast<uint8_t const*>(filter_blocks.data()) + 0,
//         reinterpret_cast<uint8_t const*>(filter_blocks.data()) + filter_blocks.size());
//     binary filter(filter_size, filter_slice);
//     const uint64_t from_height = request.from_height();
//     block_database_->fetch_stealth(filter, from_height,
//         replier_.make_handler<protocol::blockchain::fetch_stealth_handler>(
//             request.handler(),
//             [] (const code& error, chain::stealth_compact::list const& stealth,
//                 protocol::blockchain::fetch_stealth_handler& handler) -> void
//             {
//                 handler.set_error(error.value());
//                 for (auto const& entry : stealth)
//                 {
//                     auto* stealth_compact = handler.add_stealth();
//                     converter{}.to_protocol(entry.ephemeral_public_key_hash, *stealth_compact->mutable_ephemeral_public_key_hash());
//                     converter{}.to_protocol(entry.public_key_hash, *stealth_compact->mutable_public_key_hash());
//                     converter{}.to_protocol(entry.transaction_hash, *stealth_compact->mutable_transaction_hash());
//                 }
//             }));

//     protocol::void_reply reply;
//     return reply;
// }

// //! void block_chain_impl::filter_blocks(message::get_data::ptr message,
// //!     result_handler handler);
// static protocol::void_reply dispatch_filter_blocks(
//     const protocol::blockchain::filter_blocks_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     message::get_data::ptr message = std::make_shared<message::get_data>();
//     message->inventories.reserve(request.message_size());
//     for (auto const& entry : request.message())
//     {
//         message::inventory_vector inventory_vector;
//         inventory_vector.type = static_cast<message::inventory_vector::type_id>(entry.type());
//         converter{}.from_protocol(&entry.hash(), inventory_vector.hash);

//         message->inventories.push_back(std::move(inventory_vector));
//     }
//     block_database_->filter_blocks(message,
//         replier_.make_handler<protocol::blockchain::filter_blocks_handler>(
//             request.handler(),
//             [] (const code& error,
//                 protocol::blockchain::filter_blocks_handler& handler) -> void
//             {
//                 handler.set_error(error.value());
//             }));

//     protocol::void_reply reply;
//     return reply;
// }

// //! void block_chain_impl::filter_orphans(message::get_data::ptr message,
// //!     result_handler handler);
// static protocol::void_reply dispatch_filter_orphans(
//     const protocol::blockchain::filter_orphans_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     message::get_data::ptr message = std::make_shared<message::get_data>();
//     message->inventories.reserve(request.message_size());
//     for (auto const& entry : request.message())
//     {
//         message::inventory_vector inventory_vector;
//         inventory_vector.type = static_cast<message::inventory_vector::type_id>(entry.type());
//         converter{}.from_protocol(&entry.hash(), inventory_vector.hash);

//         message->inventories.push_back(std::move(inventory_vector));
//     }
//     block_database_->filter_orphans(message,
//         replier_.make_handler<protocol::blockchain::filter_orphans_handler>(
//             request.handler(),
//             [] (const code& error,
//                 protocol::blockchain::filter_orphans_handler& handler) -> void
//             {
//                 handler.set_error(error.value());
//             }));

//     protocol::void_reply reply;
//     return reply;
// }

// //! void block_chain_impl::filter_transactions(message::get_data::ptr message,
// //!     result_handler handler);
// static protocol::void_reply dispatch_filter_transactions(
//     const protocol::blockchain::filter_transactions_request& request)
// {
//     BITCOIN_ASSERT(block_database_);

//     message::get_data::ptr message = std::make_shared<message::get_data>();
//     message->inventories.reserve(request.message_size());
//     for (auto const& entry : request.message())
//     {
//         message::inventory_vector inventory_vector;
//         inventory_vector.type = static_cast<message::inventory_vector::type_id>(entry.type());
//         converter{}.from_protocol(&entry.hash(), inventory_vector.hash);

//         message->inventories.push_back(std::move(inventory_vector));
//     }
//     block_database_->filter_transactions(message,
//         replier_.make_handler<protocol::blockchain::filter_transactions_handler>(
//             request.handler(),
//             [] (const code& error,
//                 protocol::blockchain::filter_transactions_handler& handler) -> void
//             {
//                 handler.set_error(error.value());
//             }));

//     protocol::void_reply reply;
//     return reply;
// }



// //!
// zmq::message dispatch(
//     const protocol::blockchain::request& request)
// {
//     zmq::message reply;
//     switch (request.request_type_case())
//     {
//     case protocol::blockchain::request::kPool:
//     {
//         dispatch(request.pool());
//         break;
//     }
//     case protocol::blockchain::request::kStart:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_start(request.start()));
//         break;
//     }
//     case protocol::blockchain::request::kStop:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_stop(request.stop()));
//         break;
//     }
//     case protocol::blockchain::request::kClose:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_close(request.close()));
//         break;
//     }
//     case protocol::blockchain::request::kGetGapRange:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_get_gap_range(request.get_gap_range()));
//         break;
//     }
//     case protocol::blockchain::request::kGetNextGap:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_get_next_gap(request.get_next_gap()));
//         break;
//     }
//     case protocol::blockchain::request::kGetDifficulty:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_get_difficulty(request.get_difficulty()));
//         break;
//     }
//     case protocol::blockchain::request::kGetHeader:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_get_header(request.get_header()));
//         break;
//     }
//     case protocol::blockchain::request::kGetHeight:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_get_height(request.get_height()));
//         break;
//     }
//     case protocol::blockchain::request::kGetLastHeight:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_get_last_height(request.get_last_height()));
//         break;
//     }
//     case protocol::blockchain::request::kGetOutpointTransaction:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_get_outpoint_transaction(request.get_outpoint_transaction()));
//         break;
//     }
//     case protocol::blockchain::request::kGetTransaction:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_get_transaction(request.get_transaction()));
//         break;
//     }
//     case protocol::blockchain::request::kGetTransactionHeight:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_get_transaction_height(request.get_transaction_height()));
//         break;
//     }
//     case protocol::blockchain::request::kImport:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_import(request.import()));
//         break;
//     }
//     case protocol::blockchain::request::kPush:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_push(request.push()));
//         break;
//     }
//     case protocol::blockchain::request::kPopFrom:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_pop_from(request.pop_from()));
//         break;
//     }
//     case protocol::blockchain::request::kStore:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_store(request.store()));
//         break;
//     }
//     case protocol::blockchain::request::kFetchBlock:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_fetch_block(request.fetch_block()));
//         break;
//     }
//     case protocol::blockchain::request::kFetchBlockHeader:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_fetch_block_header(request.fetch_block_header()));
//         break;
//     }
//     case protocol::blockchain::request::kFetchMerkleBlock:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_fetch_merkle_block(request.fetch_merkle_block()));
//         break;
//     }
//     case protocol::blockchain::request::kFetchBlockTransactionHashes:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_fetch_block_transaction_hashes(request.fetch_block_transaction_hashes()));
//         break;
//     }
//     case protocol::blockchain::request::kFetchBlockLocator:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_fetch_block_locator(request.fetch_block_locator()));
//         break;
//     }
//     case protocol::blockchain::request::kFetchLocatorBlockHashes:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_fetch_locator_block_hashes(request.fetch_locator_block_hashes()));
//         break;
//     }
//     case protocol::blockchain::request::kFetchLocatorBlockHeaders:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_fetch_locator_block_headers(request.fetch_locator_block_headers()));
//         break;
//     }
//     case protocol::blockchain::request::kFetchBlockHeight:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_fetch_block_height(request.fetch_block_height()));
//         break;
//     }
//     case protocol::blockchain::request::kFetchLastHeight:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_fetch_last_height(request.fetch_last_height()));
//         break;
//     }
//     case protocol::blockchain::request::kFetchTransaction:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_fetch_transaction(request.fetch_transaction()));
//         break;
//     }
//     case protocol::blockchain::request::kFetchTransactionIndex:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_fetch_transaction_index(request.fetch_transaction_index()));
//         break;
//     }
//     case protocol::blockchain::request::kFetchSpend:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_fetch_spend(request.fetch_spend()));
//         break;
//     }
//     case protocol::blockchain::request::kFetchHistory:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_fetch_history(request.fetch_history()));
//         break;
//     }
//     case protocol::blockchain::request::kFetchStealth:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_fetch_stealth(request.fetch_stealth()));
//         break;
//     }
//     case protocol::blockchain::request::kFilterBlocks:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_filter_blocks(request.filter_blocks()));
//         break;
//     }
//     case protocol::blockchain::request::kFilterOrphans:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_filter_orphans(request.filter_orphans()));
//         break;
//     }
//     case protocol::blockchain::request::kFilterTransactions:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_filter_transactions(request.filter_transactions()));
//         break;
//     }
//     case protocol::blockchain::request::kSubscribeReorganize:
//     {
//         reply.enqueue_protobuf_message(
//             dispatch_subscribe_reorganize(request.subscribe_reorganize()));
//         break;
//     }
//     }
//     return reply;
// }

}} // namespace libbitcoin::blockchain
