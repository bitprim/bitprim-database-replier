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
#ifndef LIBBITCOIN_DATABASE_REPLIER_DATABASE_HPP_
#define LIBBITCOIN_DATABASE_REPLIER_DATABASE_HPP_

#include <memory>
#include <boost/optional.hpp>

//#include <bitcoin/database.hpp>
//#include <bitcoin/database/define.hpp>
#include <bitcoin/database/data_base.hpp>


#include <bitcoin/protocol/database.pb.h>
#include <bitcoin/protocol/replier.hpp>
#include <bitcoin/protocol/zmq/message.hpp>

using namespace libbitcoin::protocol;

namespace libbitcoin { namespace database {

extern /*BCB_INTERNAL*/ replier replier_;
extern /*BCB_INTERNAL*/ boost::optional<data_base> data_base_;

zmq::message /*BCB_INTERNAL*/ dispatch(
    protocol::database::request const& request);

}} // namespace libbitcoin::database

#endif /*LIBBITCOIN_DATABASE_REPLIER_DATABASE_HPP_*/
