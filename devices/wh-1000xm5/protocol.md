# sony wh-1000xm5

the headphones take commands over bluetooth classic, on an rfcomm channel that sony
calls "Serial HPC". the same protocol carries noise cancelling, ambient sound, the
battery readout and much more; this entry covers only the first three. facts marked
"seen" were observed on one unit, firmware 2.5.1, from a mac.

## service and channel

- the control service has the uuid `956c7b26-d49a-4ba8-b03f-b17d393cb6e2`. older sony
  models use a different uuid, which the xm5 does not serve.
- the rfcomm channel number comes from the service record for that uuid. a mac that
  has paired with the headphones keeps their service records, so no sdp query is
  needed. it was channel 9 on the unit seen, but look it up every time; never
  hardcode it.
- the headphones must be connected to the mac, as they are for audio. audio keeps
  playing while the control channel is open (seen: open, talk and close take one
  to two seconds).
- the phone's sony app may hold the control channel while it is open. close it, or
  turn the phone's bluetooth off, before driving the headphones from the mac.

## framing

every message is one frame:

| field | bytes | value |
|---|---|---|
| start | 1 | `3e` |
| data type | 1 | `0c` command data, `01` ack |
| seq | 1 | `00` or `01` |
| length | 4 | the payload's length before escaping, big-endian |
| payload | n | the command |
| checksum | 1 | see below |
| end | 1 | `3c` |

frames can share an rfcomm chunk, and one frame can be split across two chunks, so
a reader keeps the bytes after the last whole frame until the rest arrives.

## escaping

between the start and end markers (checksum included), the bytes `3c`, `3d` and `3e`
are sent as `3d` followed by the byte with bit 4 cleared (the byte and `ef`): `3e`
goes out as `3d 2e`. to undo it, drop each `3d` and set bit 4 of the byte after it
(or it with `10`). so an unescaped `3e` or `3c` is always a marker. seen: a battery reply of 62% arrived as
`3e 0c 00 00000004 23 00 3d 2e 00 71 3c`, payload `23 00 3e 00`.

## checksum

the sum of the data type, seq, length and payload bytes (unescaped), mod 256.

## sequence and acks

- the first frame sent uses seq 0.
- the headphones ack each data frame with `3e 01 SS 00000000 CK 3c`, and `SS` is the
  seq to use for the next one: 1 minus the seq just sent. an ack carrying anything
  else is stale (the ack for a resent frame, say); ignore it, or the next frame goes
  out with an old seq, and the headphones ack it as a resend without acting on it.
- every data frame from the headphones is acked the same way, with 1 minus its seq.
  ack it at once: the headphones resend an unacked frame about every 0.75 s (seen).
- one command at a time: send it, then wait for its ack and its reply.
- the conversation opens with a handshake. if it gets no answer in 1.25 s, send it
  once more.

## commands

all are data frames (type `0c`); the driver sends nothing else besides acks.

| action | send | reply |
|---|---|---|
| handshake | `00 00` | `01 00`, a 4-byte version and 2 flag bytes; seen `01 00 03 00 20 16 00 00` |
| read noise control | `66 17` | `67 17 ST SW MD VF LV` |
| set noise control | `68 17 01 SW MD VF LV` | an ack, then a change notice `69 17 01 SW MD VF LV` (seen) |
| battery | `22 00` | `23 00 LV CS` |

- `ST`: `01` means a final value.
- `SW`: noise control on (`01`) or off (`00`).
- `MD`: `00` noise cancelling, `01` ambient sound.
- `VF`: voice focus, `01` on.
- `LV` (noise control): the ambient level, 0 to 20. a set sends back the level just
  read, so changing the mode keeps it.
- `LV` (battery): percent, 0 to 100.
- `CS`: `00` not charging, `01` charging, `02` unknown, `03` charged.
- `17` picks the noise control layout with the dual noise cancelling switch and
  seamless ambient level. some models use `15` instead; the unit seen acks `66 15`
  but never answers it.

what the driver's commands send:

| command | sends | prints |
|---|---|---|
| `anc on` | `68 17 01 01 00 00 LV` | `noise cancelling on` |
| `anc off`, `ambient off` | `68 17 01 00 00 00 LV` | `noise control off` |
| `ambient on` | `68 17 01 01 01 VF LV` | `ambient on` |
| `battery` | `22 00` | e.g. `battery 86%, not charging` |
| `status` | `66 17` | `noise control off`, `noise cancelling on`, or e.g. `ambient on, level 20` |

each set first reads the state, for `VF` and `LV`.

example frames, all seen working:

- handshake: `3e 0c 00 00000002 0000 0e 3c`
- battery: `3e 0c 01 00000002 2200 31 3c`
- noise cancelling on, level 20: `3e 0c 00 00000007 68170101000014 a8 3c`

## unsolicited frames

the headphones also send data frames nobody asked for, in the middle of an
exchange. seen: `a5 01 00 02 01`, which arrived between the ack for `66 17` and its
`67` reply. ack every data frame, and ignore any whose first byte isn't the one the
reply being waited for starts with.

## sources

- [mos9527/SonyHeadphonesClient](https://github.com/mos9527/SonyHeadphonesClient)
  (commit 5e50423, `libmdr/include/mdr/ProtocolV2T1.hpp`), mit license
- [gadgetbridge](https://codeberg.org/Freeyourgadget/Gadgetbridge), its sony
  headphones support, agpl-3.0 license
- [vyomjain6904/sony-headphones-linux](https://github.com/vyomjain6904/sony-headphones-linux),
  mit license; it was tested on an xm5 with firmware 2.5.1
- [Plutoberth/SonyHeadphonesClient](https://github.com/Plutoberth/SonyHeadphonesClient),
  mit license
- [AndreasOlofsson/mdr-protocol](https://github.com/AndreasOlofsson/mdr-protocol),
  no license
- [whitebeard10/SonyCompanionApp](https://github.com/whitebeard10/SonyCompanionApp),
  no license

no code was taken from these projects; they were used as protocol references only.
