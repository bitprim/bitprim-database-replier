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

#include <bitcoin/bitcoin/utility/binary.hpp>

using namespace libbitcoin::protocol;

namespace libbitcoin { namespace database {


//TODO: Fer: mover de aca a un lugar mas apropiado
std::string pack_hash(hash_digest in) {
    return std::string(in.begin(), in.end());
}



//TODO: Fer: mover de aca a un lugar mas apropiado
bool to_protocol(block_result const& blk_result, protocol::block_result& result) {
    
	if (blk_result) {

		result.set_valid(true);

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
		
		result.set_hash(pack_hash(blk_result.hash()));
		result.set_height(blk_result.height());
		result.set_bits(blk_result.bits());
		result.set_timestamp(blk_result.timestamp());
		result.set_version(blk_result.version());
		result.set_transaction_count(blk_result.transaction_count());
	} else {
    	result.set_valid(false);
	}
    
    return true;
}

bool to_protocol(transaction_result const& tx_result, protocol::transaction_result& result) {

	if (tx_result){
		result.set_valid(true);
		auto mutable_transaction = result.mutable_transaction();
		if (!converter{}.to_protocol(tx_result.transaction(), *mutable_transaction)) {
		    result.clear_transaction();
		    return false;
		}
		result.set_hash(pack_hash(tx_result.hash()));
		result.set_height(tx_result.height());
		result.set_position(tx_result.position());
    }
	else{
		result.set_valid(false);
	}
    return true;
}

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

bool from_protocol(protocol::binary const* binary, libbitcoin::binary& result) {
    if (binary == nullptr)
        return false;

    const auto blocks_text = binary->blocks();
    const data_chunk data(blocks_text.begin(), blocks_text.end());

    //binary::binary(size_type size, data_slice blocks)
    result = libbitcoin::binary(data.size(), data);
    
    return true;
}


bool to_protocol(chain::stealth_compact const& s_compact, protocol::stealth_compact& result) {
    
    result.set_ephemeral_public_key_hash(pack_hash(s_compact.ephemeral_public_key_hash));
    result.set_transaction_hash(pack_hash(s_compact.transaction_hash));
  
    auto mutable_public_key_hash = result.mutable_public_key_hash();
    if (!converter{}.to_protocol(s_compact.public_key_hash, *mutable_public_key_hash)) {
        result.clear_public_key_hash();
        return false;
    }
    
    return true;
}


// ----------------------------------------------------------------



boost::optional<data_base> data_base_;

//! bool block_database::top(size_t& out_height) const;
static protocol::database::top_reply dispatch_top(
    const protocol::database::top_request& request) {

    BITCOIN_ASSERT(data_base_);

    size_t out_height;
    bool const result = data_base_->blocks().top(out_height);

    protocol::database::top_reply reply;
    reply.set_out_height(out_height);
    reply.set_result(result);
    
    //std::cout << "dispatch_top - out_height: "<< out_height <<"\n";

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

	//std::cout << "dispatch_get - reply.result().height(): " << reply.result().height() << "\n";

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
    
    for (auto const& gap : out_gaps) {
        reply.add_out_gaps(gap);
    }

    return reply;
}


// TODO: Nuevo Feb2017
//! bool data_base::begin_insert() const;
static protocol::database::begin_insert_reply dispatch_begin_insert(
    const protocol::database::begin_insert_request& request) {

    BITCOIN_ASSERT(data_base_);

    bool const result = data_base_->begin_insert();

    protocol::database::begin_insert_reply reply;
    reply.set_result(result);
    return reply;    
}

// TODO: Nuevo Feb2017
//! bool data_base::end_insert() const;
static protocol::database::end_insert_reply dispatch_end_insert(
    const protocol::database::end_insert_request& request) {

    BITCOIN_ASSERT(data_base_);

    bool const result = data_base_->end_insert();

    protocol::database::end_insert_reply reply;
    reply.set_result(result);
    return reply;    
}

//! (OLD) bool data_base::insert(const chain::block& block, size_t height)
//! (NEW) code data_base::insert(const chain::block& block, size_t height);
static protocol::database::insert_block_reply dispatch_insert_block(
    const protocol::database::insert_block_request& request) {

    BITCOIN_ASSERT(data_base_);

    size_t height = request.height();
    chain::block block;
    //PARSE BLOCK FROM MESSAGE
    
    //TODO CHECK IF SUCCESFULL
    protocol::converter converter;
    converter.from_protocol(&(request.blockr()), block);
    
    // bool const result = data_base_->insert(block, height);
    auto const result = data_base_->insert(block, height);

    protocol::database::insert_block_reply reply;
    // reply.set_result(result);
    reply.set_result(result.value());
    return reply;
}

//! (OLD) bool data_base::push(const block& block, size_t height)
//! (NEW) bool data_base::push(const block& block, size_t height)
static protocol::database::push_reply dispatch_push(
    const protocol::database::push_request& request) {

    BITCOIN_ASSERT(data_base_);

    size_t height = request.height();
    
    chain::block block;
    converter{}.from_protocol(&request.block(), block);
    //TODO CHECK IF SUCCESFULL

    //bool const result = data_base_->push(block, height);
    auto const result = data_base_->push(block, height);

    protocol::database::push_reply reply;
    // reply.set_result(result);
    reply.set_result(result.value());
    return reply;
}


// TODO: Eliminado en Feb2017
// //! bool data_base::pop_above(block::list& out_blocks, const hash_digest& fork_hash)
// static protocol::database::pop_above_reply dispatch_pop_above(
//     const protocol::database::pop_above_request& request) {

//     BITCOIN_ASSERT(data_base_);

//     hash_digest fork_hash;
//     converter{}.from_protocol(&request.fork_hash(), fork_hash);

//     chain::block::list out_blocks;
//     bool const result = data_base_->pop_above(out_blocks, fork_hash);

//     protocol::database::pop_above_reply reply;
//     reply.set_result(result);

//     auto repeated_out_blocks = reply.mutable_out_blocks();

//     for (auto const& out_block : out_blocks) {
//         converter{}.to_protocol(out_block, *(repeated_out_blocks->Add()));
//     }

//     return reply;
// }


//! bool store::flush_lock() const
static protocol::database::flush_lock_reply dispatch_flush_lock(
    const protocol::database::flush_lock_request& request) {

    //std::cout << "flush_lock - 1\n";

    BITCOIN_ASSERT(data_base_);

    bool const result = data_base_->flush_lock();

    protocol::database::flush_lock_reply reply;
    reply.set_result(result);
    
    return reply;
}

//! bool store::flush_unlock() const
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

//! (OLD) bool store::begin_write(bool lock)
//! (NEW) bool store::begin_write() const;
static protocol::database::begin_write_reply dispatch_begin_write(
    const protocol::database::begin_write_request& request) {

    BITCOIN_ASSERT(data_base_);

    // bool lock = request.lock();
    // bool const result = data_base_->begin_write(lock);
    bool const result = data_base_->begin_write();

    protocol::database::begin_write_reply reply;
    reply.set_result(result);
    return reply;
}

//! (OLD) bool store::end_write(bool unlock)
//! (NEW )bool store::end_write() const;
static protocol::database::end_write_reply dispatch_end_write(
    const protocol::database::end_write_request& request) {

    BITCOIN_ASSERT(data_base_);

    // bool unlock = request.unlock();
    // bool const result = data_base_->end_write(unlock);
    bool const result = data_base_->end_write();

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


//! (OLD) transaction_result transaction_database::get(const hash_digest& hash) const
//! (NEW) transaction_result transaction_database::get(const hash_digest& hash, size_t fork_height, bool require_confirmed) const;
static protocol::database::get_transaction_reply dispatch_get_transaction(
    const protocol::database::get_transaction_request& request) {

    BITCOIN_ASSERT(data_base_);
   
    hash_digest hash;
    converter{}.from_protocol(&request.hash(), hash);
    transaction_result const result = data_base_->transactions().get(hash, request.fork_height(), request.require_confirmed());

    protocol::database::get_transaction_reply reply;
    to_protocol(result, *reply.mutable_result());

    return reply;
}


//bool transaction_database::get_output(chain::output& out_output, size_t& out_height, bool& out_coinbase, 
//    const chain::output_point& point, size_t fork_height, bool require_confirmed) const
static protocol::database::get_transaction_output_reply dispatch_get_transaction(
    const protocol::database::get_transaction_output_request& request) {

    BITCOIN_ASSERT(data_base_);
   
    chain::output output;
    size_t out_height;
    bool out_coinbase;    
    
    chain::output_point outpoint;
    converter{}.from_protocol(&request.point(), outpoint);
    size_t fork_height = request.fork_height();
    bool require_confirmed = request.require_confirmed();

    const bool result = data_base_->transaction().get_output(output,out_height,out_coinbase, outpoint,fork_height,require_confirmed);

    protocol::blockchain::get_transaction_output_reply reply;
    reply.set_result(result);
    if (result)
    {
        converter{}.to_protocol(output, *reply.mutable_out_output());
        reply.set_out_height(out_height);
        reply.set_out_coinbase(out_coinbase);
    }
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
        
    auto repeated_result = reply.mutable_result();

    for (auto const& s_compact : result) {
        to_protocol(s_compact, *(repeated_result->Add()));
    }
    

    return reply;
}


// -----------------------------------------------------------


//!
zmq::message dispatch(
    const protocol::database::request& request)
{
 //    std::cout << "receiving a ZMQ/Protobuf message\n";
	// request.PrintDebugString();
    
    zmq::message reply;
    switch (request.request_type_case()) {
        case protocol::database::request::kTop: {
            // request.PrintDebugString();
            reply.enqueue_protobuf_message(
                dispatch_top(request.top()));
            // reply.PrintDebugString();
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
        
        


        // TODO: Nuevo Feb2017
        case protocol::database::request::kBeginInsert: {
            reply.enqueue_protobuf_message(
                dispatch_begin_insert(request.begin_insert()));
            break;
        }
        // TODO: Nuevo Feb2017
        case protocol::database::request::kEndInsert: {
            reply.enqueue_protobuf_message(
                dispatch_end_insert(request.end_insert()));
            break;
        }
        case protocol::database::request::kInsertBlock: {
            // request.PrintDebugString();
            reply.enqueue_protobuf_message(
                dispatch_insert_block(request.insert_block()));
            // reply.PrintDebugString();
            break;
        }
        case protocol::database::request::kPush: {
            reply.enqueue_protobuf_message(
                dispatch_push(request.push()));
            break;
        }

        // TODO: Eliminado en Feb2017
        // case protocol::database::request::kPopAbove: {
        //     reply.enqueue_protobuf_message(
        //         dispatch_pop_above(request.pop_above()));
        //     break;
        // }
        
        
        
        
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
        case protocol::database::request::kGetTransactionOutput: {
            reply.enqueue_protobuf_message(
                dispatch_get_transaction_output(request.get_transaction_output()));
            break;
        }
        
        

    }
    return reply;
}


}} // namespace libbitcoin::blockchain
