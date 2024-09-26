const std = @import("std");
const cli = @import("zig-cli");

const Sha1 = std.crypto.hash.Sha1;

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

    fn encode(self: BencodeValue, alloc: std.mem.Allocator) ![]u8 {
        switch (self) {
            .String => |str| return std.fmt.allocPrint(alloc, "{d}:{s}", .{ str.len, str }),
            .Int => |int| return std.fmt.allocPrint(alloc, "i{d}e", .{int}),
            .List => |list| {
                var bencoded = std.ArrayList(u8).init(alloc);

                try bencoded.append('l');
                for (list.items) |item| {
                    const item_bencoded = try item.encode(alloc);
                    defer alloc.free(item_bencoded);

                    try bencoded.appendSlice(item_bencoded);
                }
                try bencoded.append('e');

                return bencoded.toOwnedSlice();
            },
            .Dict => |dict| {
                var bencoded = std.ArrayList(u8).init(alloc);

                try bencoded.append('d');
                var iter = dict.iterator();
                while (iter.next()) |entry| {
                    const key = BencodeValue{ .String = entry.key_ptr.* };

                    const key_bencoded = try key.encode(alloc);
                    defer allocator.free(key_bencoded);
                    try bencoded.appendSlice(key_bencoded);

                    const value = entry.value_ptr.*;

                    const value_bencoded = try value.encode(alloc);
                    defer allocator.free(value_bencoded);
                    try bencoded.appendSlice(value_bencoded);
                }
                try bencoded.append('e');

                return bencoded.toOwnedSlice();
            },
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

const TorrentInfo = struct {
    announce: []const u8,
    info_hash: [Sha1.digest_length]u8,
    length: i64,
    piece_length: i64,
    pieces: [][]const u8,

    fn deinit(self: TorrentInfo, alloc: std.mem.Allocator) void {
        alloc.free(self.announce);
        for (self.pieces) |piece| alloc.free(piece);
        alloc.free(self.pieces);
    }
};

fn parseTorrentFile(alloc: std.mem.Allocator, file_path: []const u8) !TorrentInfo {
    const torrent_file = try std.fs.cwd().readFileAlloc(alloc, file_path, std.math.maxInt(usize));
    defer alloc.free(torrent_file);

    var fb = std.io.fixedBufferStream(torrent_file);
    const reader = fb.reader();

    var decoder = BencodeDecoder.init(alloc);
    var result = try decoder.decode(reader);
    defer result.deinit(alloc);

    if (result != .Dict) return error.InvalidTorrentFile;

    const announce = result.Dict.get("announce") orelse return error.InvalidTorrentFile;
    const info = result.Dict.get("info") orelse return error.InvalidTorrentFile;

    if (info != .Dict) return error.InvalidTorrentFile;

    const info_bencoded = try info.encode(allocator);
    defer allocator.free(info_bencoded);

    var info_hash: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(info_bencoded, &info_hash, .{});

    const length = info.Dict.get("length") orelse return error.InvalidTorrentFile;
    const piece_length = info.Dict.get("piece length") orelse return error.InvalidTorrentFile;

    var pieces_arr = std.ArrayList([]const u8).init(alloc);
    const pieces = info.Dict.get("pieces") orelse return error.InvalidTorrentFile;
    var pieces_iter = std.mem.window(u8, pieces.String, 20, 20);
    while (pieces_iter.next()) |piece| try pieces_arr.append(try alloc.dupe(u8, piece));

    return .{
        .announce = try alloc.dupe(u8, announce.String),
        .info_hash = info_hash,
        .length = length.Int,
        .piece_length = piece_length.Int,
        .pieces = try pieces_arr.toOwnedSlice(),
    };
}

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
                    cli.Command{
                        .name = "info",
                        .target = cli.CommandTarget{
                            .action = cli.CommandAction{
                                .exec = printInfo,
                                .positional_args = cli.PositionalArgs{
                                    .required = try r.mkSlice(
                                        cli.PositionalArg,
                                        &.{
                                            .{
                                                .name = "torrent-file",
                                                .value_ref = r.mkRef(&config.arg1),
                                            },
                                        },
                                    ),
                                },
                            },
                        },
                    },
                    cli.Command{
                        .name = "peers",
                        .target = cli.CommandTarget{
                            .action = cli.CommandAction{
                                .exec = printPeers,
                                .positional_args = cli.PositionalArgs{
                                    .required = try r.mkSlice(
                                        cli.PositionalArg,
                                        &.{
                                            .{
                                                .name = "torrent-file",
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

fn printInfo() !void {
    const writer = std.io.getStdOut().writer();

    const torrent_info = try parseTorrentFile(allocator, config.arg1);
    defer torrent_info.deinit(allocator);

    try writer.print("Tracker URL: {s}\n", .{torrent_info.announce});
    try writer.print("Length: {d}\n", .{torrent_info.length});
    try writer.print("Info Hash: {s}\n", .{std.fmt.fmtSliceHexLower(&torrent_info.info_hash)});
    try writer.print("Piece Length: {d}\n", .{torrent_info.piece_length});

    try writer.writeAll("Piece Hashes:\n");
    for (torrent_info.pieces) |piece| std.debug.print("{s}\n", .{std.fmt.fmtSliceHexLower(piece)});
}

fn printPeers() !void {}
