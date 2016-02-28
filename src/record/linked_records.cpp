/**
 * Copyright (c) 2011-2015 libbitcoin developers (see AUTHORS)
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
#include <bitcoin/database/record/linked_records.hpp>

#include <bitcoin/bitcoin.hpp>

namespace libbitcoin {
namespace database {

linked_records::linked_records(record_manager& manager)
  : manager_(manager)
{
}

array_index linked_records::create()
{
    // Insert new record with empty next value.
    return insert(empty);
}

array_index linked_records::insert(array_index next)
{
    static_assert(sizeof(array_index) == sizeof(uint32_t),
        "array_index incorrect size");

    // Create new record.
    auto record = manager_.new_record();
    const auto data = manager_.get_record(record);

    // Write next value at first 4 bytes of record.
    auto serial = make_serializer(data);

    // MUST BE ATOMIC
    serial.write_4_bytes_little_endian(next);
    return record;
}

array_index linked_records::next(array_index index) const
{
    const auto data = manager_.get_record(index);
    return from_little_endian_unsafe<array_index>(data);
}

uint8_t* linked_records::get(array_index index) const
{
    return manager_.get_record(index) + sizeof(array_index);
}

} // namespace database
} // namespace libbitcoin
