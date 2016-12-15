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


#include <functional>
#include <iostream>
#include <ostream>
#include <memory>

#include <boost/core/null_deleter.hpp>
#include <boost/optional.hpp>
#include <boost/format.hpp>
#include <boost/utility/in_place_factory.hpp>


// #include <bitcoin/blockchain.hpp>
// #include <bitcoin/blockchain/configuration.hpp>
// #include <bitcoin/blockchain/define.hpp>
// #include <bitcoin/blockchain/parser.hpp>
// #include <bitcoin/blockchain/settings.hpp>

// #include "database.hpp"
// #include "configuration.hpp"
// #include "define.hpp"
// #include "parser.hpp"

#include <bitcoin/database/database_replier.hpp>
#include <bitcoin/database/configuration.hpp>
#include <bitcoin/database/define_replier.hpp>
#include <bitcoin/database/parser.hpp>


#include <bitcoin/protocol/database.pb.h>
#include <bitcoin/protocol/replier.hpp>
#include <bitcoin/protocol/zmq/context.hpp>
#include <bitcoin/protocol/zmq/message.hpp>
#include <bitcoin/protocol/zmq/socket.hpp>

using namespace libbitcoin::protocol;

namespace libbitcoin {
namespace database {

using boost::format;

static zmq::context context;
replier replier_(context);

//std::ostream output_;
//std::ostream error_;



#define BN_INITCHAIN_EXISTS \
    "Failed because the directory %1% already exists."
#define BN_INITCHAIN_NEW \
    "Failed to create directory %1% with error, '%2%'."
#define BN_USING_CONFIG_FILE \
    "Using config file: %1%"
#define BN_USING_DEFAULT_CONFIG \
    "Using default configuration settings."
#define BN_LOG_HEADER \
    "================= startup =================="

static constexpr int directory_exists = 0;

void initialize_output(parser const& metadata) {
    LOG_DEBUG(LOG_DATABASE) << BN_LOG_HEADER;
    LOG_INFO(LOG_DATABASE) << BN_LOG_HEADER;
    LOG_WARNING(LOG_DATABASE) << BN_LOG_HEADER;
    LOG_ERROR(LOG_DATABASE) << BN_LOG_HEADER;
    LOG_FATAL(LOG_DATABASE) << BN_LOG_HEADER;

    const auto& file = metadata.configured.file;

    if (file.empty()) {
        LOG_INFO(LOG_DATABASE) << BN_USING_DEFAULT_CONFIG;
    } else {
        LOG_INFO(LOG_DATABASE) << format(BN_USING_CONFIG_FILE) % file;
    }
}

bool do_initchain(parser const& metadata) {
    initialize_output(metadata);

    boost::system::error_code ec;
    const auto& directory = metadata.configured.database.directory;

    if (create_directories(directory, ec)) {
        // LOG_INFO(LOG_DATABASE) << format(BN_INITIALIZING_CHAIN) % directory;

        // // Unfortunately we are still limited to a choice of hardcoded chains.
        // const auto genesis = metadata.configured.chain.use_testnet_rules ?
        //     block::genesis_testnet() : block::genesis_mainnet();

        // const auto& settings = metadata.configured.database;
        // const auto result = data_base(settings).create(genesis);

        // LOG_INFO(LOG_DATABASE) << BN_INITCHAIN_COMPLETE;
        // return result;
        return true;
    }

    if (ec.value() == directory_exists) {
        LOG_ERROR(LOG_DATABASE) << format(BN_INITCHAIN_EXISTS) % directory;
        return false;
    }

    LOG_ERROR(LOG_DATABASE) << format(BN_INITCHAIN_NEW) % directory % ec.message();
    return false;
}

bool init_logger(parser const& metadata, std::ostream& output_, std::ostream& error_) {

    const auto& network = metadata.configured.network;

    const log::rotable_file debug_file
    {
        network.debug_file,
        network.archive_directory,
        network.rotation_size,
        network.maximum_archive_size,
        network.minimum_free_space,
        network.maximum_archive_files
    };

    const log::rotable_file error_file
    {
        network.error_file,
        network.archive_directory,
        network.rotation_size,
        network.maximum_archive_size,
        network.minimum_free_space,
        network.maximum_archive_files
    };

    log::stream console_out(&output_, boost::null_deleter());
    log::stream console_err(&error_, boost::null_deleter());

    log::initialize(debug_file, error_file, console_out, console_err);
}


static int main(parser const& metadata) {

    std::ostream output_(std::cout.rdbuf());
    std::ostream error_(std::cerr.rdbuf());

    init_logger(metadata, output_, error_);

    const auto& config = metadata.configured;
    if (config.initchain) {
        return do_initchain(metadata);
    }

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