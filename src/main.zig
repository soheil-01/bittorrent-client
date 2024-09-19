const std = @import("std");
const cli = @import("zig-cli");

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

    fn deinit(self: *BencodeValue, alloc: std.mem.Allocator) void {
        switch (self.*) {
            .String => |str| alloc.free(str),
            .List => |*list| {
                for (list.items) |*item| item.deinit(alloc);
                list.deinit();
            },
            .Dict => |*dict| {
                var iter = dict.iterator();
                while (iter.next()) |entry| {
                    alloc.free(entry.key_ptr.*);
                    entry.value_ptr.deinit(alloc);
                }
                dict.deinit();
            },
            else => {},
        }
    }
};

const BencodeDecoder = struct {
    allocator: std.mem.Allocator,

    fn init(alloc: std.mem.Allocator) BencodeDecoder {
        return .{ .allocator = alloc };
    }

    fn getCurrentByte(reader: anytype) !u8 {
        const pos = reader.context.pos;
        const byte = try reader.readByte();
        try reader.context.seekTo(pos);

        return byte;
    }

    fn decodeString(self: BencodeDecoder, reader: anytype) !BencodeValue {
        const len_str = try reader.readUntilDelimiterAlloc(self.allocator, ':', std.math.maxInt(u32));
        defer self.allocator.free(len_str);

        const len = try std.fmt.parseInt(u32, len_str, 10);

        const str = try self.allocator.alloc(u8, len);
        try reader.readNoEof(str);

        return .{ .String = str };
    }

    fn decodeInt(self: BencodeDecoder, reader: anytype) !BencodeValue {
        const int_str = try reader.readUntilDelimiterAlloc(self.allocator, 'e', std.math.maxInt(u32));
        defer self.allocator.free(int_str);

        const int = try std.fmt.parseInt(i64, int_str, 10);

        return .{ .Int = int };
    }

    fn decodeList(self: BencodeDecoder, reader: anytype) !BencodeValue {
        var list = std.ArrayList(BencodeValue).init(self.allocator);

        while (try getCurrentByte(reader) != 'e') {
            const item = try self.decode(reader);
            try list.append(item);
        }
        try reader.skipBytes(1, .{});

        return .{ .List = list };
    }

    fn decodeDict(self: BencodeDecoder, reader: anytype) !BencodeValue {
        var dict = std.StringHashMap(BencodeValue).init(self.allocator);

        while (try getCurrentByte(reader) != 'e') {
            const key = try self.decode(reader);
            const value = try self.decode(reader);

            try dict.put(key.String, value);
        }
        try reader.skipBytes(1, .{});

        return .{ .Dict = dict };
    }

    fn decode(self: BencodeDecoder, reader: anytype) anyerror!BencodeValue {
        const byte = try reader.readByte();
        switch (byte) {
            '0'...'9' => {
                try reader.context.seekBy(-1);
                return self.decodeString(reader);
            },
            'i' => return self.decodeInt(reader),
            'l' => return self.decodeList(reader),
            'd' => return self.decodeDict(reader),
            else => return error.InvalidBencode,
        }
    }
};

var config = struct {
    arg1: []const u8 = undefined,
}{};

pub fn main() !void {
    defer _ = gpa.deinit();

    var r = try cli.AppRunner.init(allocator);

    const app = cli.App{
        .command = cli.Command{
            .name = "bittorrent-client",
            .target = cli.CommandTarget{
                .subcommands = &.{
                    cli.Command{
                        .name = "decode",
                        .target = cli.CommandTarget{
                            .action = cli.CommandAction{
                                .exec = decodeBencode,
                                .positional_args = cli.PositionalArgs{
                                    .required = try r.mkSlice(
                                        cli.PositionalArg,
                                        &.{
                                            .{
                                                .name = "bencode-string",
                                                .value_ref = r.mkRef(&config.arg1),
                                            },
                                        },
                                    ),
                                },
                            },
                        },
                    },
                },
            },
        },
    };

    return r.run(&app);
}

fn decodeBencode() !void {
    const writer = std.io.getStdOut().writer();

    var fb = std.io.fixedBufferStream(config.arg1);
    const reader = fb.reader();

    var decoder = BencodeDecoder.init(allocator);
    var result = try decoder.decode(reader);
    defer result.deinit(allocator);

    try result.write(writer);
    try writer.writeByte('\n');
}
