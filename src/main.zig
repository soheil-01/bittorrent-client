const std = @import("std");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

const BencodeValue = union(enum) {
    String: []const u8,
    Int: i64,
    List: std.ArrayList(BencodeValue),
    Dict: std.StringHashMap(BencodeValue),

    fn write(self: BencodeValue, writer: anytype) !void {
        switch (self) {
            .String => |str| {
                try writer.writeByte('"');
                try writer.writeAll(str);
                try writer.writeByte('"');
            },
            .Int => |int| {
                try writer.print("{d}", .{int});
            },
            .List => |list| {
                try writer.writeByte('[');
                for (list.items, 0..) |item, i| {
                    if (i != 0) try writer.writeByte(',');
                    try item.write(writer);
                }
                try writer.writeByte(']');
            },
            .Dict => |dict| {
                try writer.writeByte('{');
                var iter = dict.iterator();
                var first = true;
                while (iter.next()) |entry| {
                    if (!first) try writer.writeByte(',');
                    first = false;

                    const key = BencodeValue{ .String = entry.key_ptr.* };
                    try key.write(writer);

                    try writer.writeByte(':');

                    const value = entry.value_ptr.*;
                    try value.write(writer);
                }
                try writer.writeByte('}');
            },
        }
    }

    fn deinit(self: *BencodeValue) void {
        switch (self.*) {
            .String => |str| allocator.free(str),
            .List => |*list| {
                for (list.items) |*item| item.deinit();
                list.deinit();
            },
            .Dict => |*dict| {
                var iter = dict.iterator();
                while (iter.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    entry.value_ptr.deinit();
                }
                dict.deinit();
            },
            else => {},
        }
    }
};

fn getCurrentByte(reader: anytype) !u8 {
    const pos = reader.context.pos;
    const byte = try reader.readByte();
    try reader.context.seekTo(pos);

    return byte;
}

fn decodeString(reader: anytype) !BencodeValue {
    const len_str = try reader.readUntilDelimiterAlloc(allocator, ':', std.math.maxInt(u32));
    defer allocator.free(len_str);

    const len = try std.fmt.parseInt(u32, len_str, 10);

    const str = try allocator.alloc(u8, len);
    try reader.readNoEof(str);

    return .{ .String = str };
}

fn decodeInt(reader: anytype) !BencodeValue {
    const int_str = try reader.readUntilDelimiterAlloc(allocator, 'e', std.math.maxInt(u32));
    defer allocator.free(int_str);

    const int = try std.fmt.parseInt(i64, int_str, 10);

    return .{ .Int = int };
}

fn decodeList(reader: anytype) !BencodeValue {
    var list = std.ArrayList(BencodeValue).init(allocator);

    while (try getCurrentByte(reader) != 'e') {
        const item = try decode(reader);
        try list.append(item);
    }
    try reader.skipBytes(1, .{});

    return .{ .List = list };
}

fn decodeDict(reader: anytype) !BencodeValue {
    var dict = std.StringHashMap(BencodeValue).init(allocator);

    while (try getCurrentByte(reader) != 'e') {
        const key = try decode(reader);
        const value = try decode(reader);

        try dict.put(key.String, value);
    }
    try reader.skipBytes(1, .{});

    return .{ .Dict = dict };
}

fn decode(reader: anytype) anyerror!BencodeValue {
    const byte = try reader.readByte();
    switch (byte) {
        '0'...'9' => {
            try reader.context.seekBy(-1);
            return decodeString(reader);
        },
        'i' => return decodeInt(reader),
        'l' => return decodeList(reader),
        'd' => return decodeDict(reader),
        else => return error.InvalidBencode,
    }
}

pub fn main() !void {
    defer _ = gpa.deinit();

    const writer = std.io.getStdOut().writer();

    var fb = std.io.fixedBufferStream("d3:foo3:bar5:helloi52ee");
    const reader = fb.reader();

    var result = try decode(reader);
    defer result.deinit();

    try result.write(writer);
    try writer.writeByte('\n');
}
