-- Copyright 2003-2015 CORE Security Technologies
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--   http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- Authors:
--          Andres Blanco (6e726d)
--

-- Protocol Type
local PROTO_TYPE = { [0] = "ACK",
	                 [1] = "ANNOUNCE",
					 [2] = "INFO_REQUEST",
					 [3] = "INFO_RESPONSE",
					 [4] = "SET_CHANNEL",
					 [5] = "START",
					 [6] = "STOP",
					 [7] = "DATA",
					 [8] = "DATA_FRAGMENT",
					 [9] = "DATA_INJECT",
					 [10] = "ERROR" }

-- Declare wiwo protocol
wiwo_protocol = Proto("WiWo", "WiWo Protocol")

function wiwo_protocol.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "WIWO"
	local subtree = tree:add(wiwo_protocol, buffer(), "WiWo Protocol Data")
	local frame_type = buffer(0,1)
	subtree:add(buffer(0, 1), "Type: " .. frame_type:uint() .. " [" .. PROTO_TYPE[frame_type:uint()] .. "]")
	pinfo.cols.info = PROTO_TYPE[frame_type:uint()]
end

-- Load ethernet type/proto
ethernet_table = DissectorTable.get("ethertype")
-- Register wiwo protocol
ethernet_table:add(0xfafa, wiwo_protocol)