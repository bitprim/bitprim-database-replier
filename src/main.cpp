/**
 * Copyright (c) 2016 Bitprim developers (see AUTHORS)
 *
 * This file is part of libbitcoin.
 *
 * libbitcoin is free software: you can redistribute it and/or modify
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

#include "database.hpp"

#include <functional>
#include <memory>
#include <boost/optional.hpp>
#include <boost/utility/in_place_factory.hpp>

// #include <bitcoin/blockchain.hpp>
// #include <bitcoin/blockchain/configuration.hpp>
// #include <bitcoin/blockchain/define.hpp>
// #include <bitcoin/blockchain/parser.hpp>
// #include <bitcoin/blockchain/settings.hpp>

#include "configuration.hpp"
#include "define.hpp"
#include "parser.hpp"

#include <bitcoin/protocol/database.pb.h>
#include <bitcoin/protocol/replier.hpp>
#include <bitcoin/protocol/zmq/context.hpp>
#include <bitcoin/protocol/zmq/message.hpp>
#include <bitcoin/protocol/zmq/socket.hpp>

using namespace libbitcoin::protocol;

namespace libbitcoin {
namespace database {

static zmq::context context;
replier replier_(context);

static int main(parser& metadata) {
    data_base_ = boost::in_place(metadata.configured.database);

    auto ec = replier_.bind(metadata.configured.database.replier);
    assert(!ec);

    while (true) {
        protocol::database::request request;
        ec = replier_.receive(request);
        assert(!ec);

        zmq::message reply = dispatch(request);
        ec = replier_.send(reply);
        assert(!ec);
    }

    return 0;
}

}} // namespace libbitcoin::database

BC_USE_LIBBITCOIN_MAIN

int libbitcoin::main(int argc, char* argv[]) {
    set_utf8_stdio();
    database::parser metadata(config::settings::mainnet);
    auto const& args = const_cast<char const**>(argv);

    if (!metadata.parse(argc, args, cerr)) {
        return console_result::failure;
    }

    return database::main(metadata);
}