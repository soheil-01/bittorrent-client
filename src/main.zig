const std = @import("std");
const cli = @import("zig-cli");

const Sha1 = std.crypto.hash.Sha1;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

const BencodeValue = union(enum) {
    String: []const u8,
    Int: i64,
    List: std.ArrayList(BencodeValue),
    Dict: std.StringArrayHashMap(BencodeValue),

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
        var dict = std.StringArrayHashMap(BencodeValue).init(self.allocator);

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

const Peer = struct {
    ip: [4]u8,
    port: u16,
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

fn parsePeers(alloc: std.mem.Allocator, peers_string: []const u8) ![]Peer {
    var peers = std.ArrayList(Peer).init(alloc);
    errdefer peers.deinit();

    var peers_iter = std.mem.window(u8, peers_string, 6, 6);
    while (peers_iter.next()) |peer| {
        var ip: [4]u8 = undefined;
        @memcpy(&ip, peer[0..4]);
        const port = std.mem.readInt(u16, peer[4..6], .big);

        try peers.append(.{ .ip = ip, .port = port });
    }

    return peers.toOwnedSlice();
}

fn urlEncode(alloc: std.mem.Allocator, input: []const u8) ![]u8 {
    var output = std.ArrayList(u8).init(alloc);
    errdefer output.deinit();

    for (input) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            try output.append(c);
        } else {
            try std.fmt.format(output.writer(), "%{X:0>2}", .{c});
        }
    }

    return output.toOwnedSlice();
}

var config = struct {
    arg1: []const u8 = undefined,
    arg2: []const u8 = undefined,
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
                    cli.Command{
                        .name = "handshake",
                        .target = cli.CommandTarget{
                            .action = cli.CommandAction{
                                .exec = peerHandshake,
                                .positional_args = cli.PositionalArgs{
                                    .required = try r.mkSlice(
                                        cli.PositionalArg,
                                        &.{
                                            .{
                                                .name = "torrent-file",
                                                .value_ref = r.mkRef(&config.arg1),
                                            },
                                            .{
                                                .name = "peer",
                                                .value_ref = r.mkRef(&config.arg2),
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

fn printPeers() !void {
    const writer = std.io.getStdOut().writer();

    const torrent_info = try parseTorrentFile(allocator, config.arg1);
    defer torrent_info.deinit(allocator);

    const info_hash_url_encoded = try urlEncode(allocator, &torrent_info.info_hash);
    defer allocator.free(info_hash_url_encoded);

    var peer_id: [20]u8 = undefined;
    std.crypto.random.bytes(&peer_id);
    const peer_id_url_encoded = try urlEncode(allocator, &peer_id);
    defer allocator.free(peer_id_url_encoded);

    const uri_text = try std.fmt.allocPrint(
        allocator,
        "{s}?info_hash={s}&peer_id={s}&port=6881&uploaded=0&downloaded=0&left={d}&compact=1",
        .{
            torrent_info.announce,
            info_hash_url_encoded,
            peer_id_url_encoded,
            torrent_info.length,
        },
    );
    defer allocator.free(uri_text);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(uri_text);
    const buf = try allocator.alloc(u8, 1024 * 1024 * 4);
    defer allocator.free(buf);

    var req = try client.open(.GET, uri, .{
        .server_header_buffer = buf,
    });
    defer req.deinit();

    try req.send();
    try req.finish();
    try req.wait();

    const body = try req.reader().readAllAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(body);

    var fb = std.io.fixedBufferStream(body);
    const reader = fb.reader();

    const decoder = BencodeDecoder.init(allocator);
    var body_decoded = try decoder.decode(reader);
    defer body_decoded.deinit(allocator);

    const peers_string = body_decoded.Dict.get("peers").?.String;
    const peers = try parsePeers(allocator, peers_string);
    defer allocator.free(peers);

    for (peers) |peer| {
        try writer.print("{d}.{d}.{d}.{d}:{d}\n", .{ peer.ip[0], peer.ip[1], peer.ip[2], peer.ip[3], peer.port });
    }
}

fn peerHandshake() !void {
    const writer = std.io.getStdOut().writer();

    const torrent_info = try parseTorrentFile(allocator, config.arg1);
    defer torrent_info.deinit(allocator);

    var iter = std.mem.split(u8, config.arg2, ":");
    const peer_ip = iter.first();
    const peer_port = try std.fmt.parseInt(u16, iter.next() orelse return error.InvalidPeer, 10);

    const peer = try std.net.Address.parseIp4(peer_ip, peer_port);
    const stream = try std.net.tcpConnectToAddress(peer);
    defer stream.close();

    var peer_id: [20]u8 = undefined;
    std.crypto.random.bytes(&peer_id);

    const data = [_]u8{19} ++ "BitTorrent protocol" ++ [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 } ++ torrent_info.info_hash ++ peer_id;
    var stream_writer = stream.writer();
    _ = try stream_writer.write(data);

    var stream_reader = stream.reader();

    var response: [68]u8 = undefined;
    _ = try stream_reader.readAll(&response);

    try writer.print("Peer ID: {s}\n", .{std.fmt.fmtSliceHexLower(response[48..])});
}
