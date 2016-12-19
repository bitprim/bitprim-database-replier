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

using namespace libbitcoin::protocol;

namespace libbitcoin { namespace database {

boost::optional<data_base> data_base_;

//! bool block_database:: top(size_t& out_height) const;
static protocol::database::top_reply dispatch_top(
    const protocol::database::top_request& request) {

    BITCOIN_ASSERT(data_base_);

    size_t out_height;
    bool const result = data_base_->blocks().top(out_height);

    protocol::database::top_reply reply;
    reply.set_out_height(out_height);
    reply.set_result(result);
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
