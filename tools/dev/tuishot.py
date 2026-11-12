#!/usr/bin/env python3
"""Runs a terminal program on a pseudo-terminal, drives it with keys and saves its screen.

usage: tuishot.py [options] -- <command> [<argument>...]

Options:
  --cols <n>            Columns of the terminal (default: 174)
  --rows <n>            Rows of the terminal (default: 44)
  --steps <steps>       What to do once the program runs (default: sleep:2)
  --text <file>         Save the screen as text
  --html <file>         Save the screen as a page with its colors
  --png <file>          Save the screen as an image; needs Chrome or Chromium
  --title <text>        Title bar of the page (default: the command)
  --font <file>         Font file for the page instead of the system's monospace
  --env <name>=<value>  Set a variable for the program; <name> alone removes it
  --chrome <path>       The browser that renders the image (default: looked up)
  --raw <file>          Save the bytes the program wrote, as they came

Steps are separated by commas or line breaks:
  sleep:<seconds>
  key:<name>            F1 to F12, up, down, left, right, pgup, pgdn, home, end, enter, esc,
                        tab, space, backspace, delete, ctrl-a to ctrl-z, or one character
  text:<characters>     typed as they are; a comma ends the step
  click:<column>x<row>  a left click, both counted from 0
  wheel:up|down[:<column>x<row>]
  resize:<columns>x<rows>
  shot:<name>           save the screen now, with -<name> added to each file name

Without a shot step the screen is saved once, when the steps are done. The program runs with
TERM=xterm-256color and COLORTERM=truecolor, and is stopped at the end.

Needs Python 3.9 or later and nothing beside it. The screen is read by a small emulator of
the xterm sequences that full-screen programs draw with: cursor movement, erasing, colors and
attributes, the alternate screen. Exits with 1 when the program ended before the steps did.
"""
import argparse
import codecs
import fcntl
import html
import math
import os
import pty
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unicodedata

KEYS = {
    'f1': '\x1bOP', 'f2': '\x1bOQ', 'f3': '\x1bOR', 'f4': '\x1bOS', 'f5': '\x1b[15~',
    'f6': '\x1b[17~', 'f7': '\x1b[18~', 'f8': '\x1b[19~', 'f9': '\x1b[20~', 'f10': '\x1b[21~',
    'f11': '\x1b[23~', 'f12': '\x1b[24~',
    'up': '\x1b[A', 'down': '\x1b[B', 'right': '\x1b[C', 'left': '\x1b[D',
    'home': '\x1b[H', 'end': '\x1b[F', 'pgup': '\x1b[5~', 'pgdn': '\x1b[6~',
    'enter': '\r', 'esc': '\x1b', 'tab': '\t', 'space': ' ', 'backspace': '\x7f',
    'delete': '\x1b[3~',
}
for letter in 'abcdefghijklmnopqrstuvwxyz':
    KEYS['ctrl-' + letter] = chr(ord(letter) - 96)

# Colors 0 to 15, as a dark terminal theme shows them.
PALETTE = [
    '#0b0e14', '#ff7b72', '#3fb950', '#d29922', '#58a6ff', '#d2a8ff', '#39c5cf', '#c9d1d9',
    '#7d8590', '#ffa198', '#56d364', '#e3b341', '#79c0ff', '#e2c5ff', '#56d4dd', '#f0f6fc',
]
FOREGROUND, BACKGROUND = '#c9d1d9', '#0b0e14'

FONT_PX, LINE_PX, CELL_PX = 12, 17, 7.25
BAR_PX, PAD_X, PAD_TOP, PAD_BOTTOM = 28, 14, 10, 8

BROWSERS = [
    'chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable', 'chrome',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
]


def indexed_color(n):
    if n < 16:
        return PALETTE[n]
    if n < 232:
        n -= 16
        levels = [0, 95, 135, 175, 215, 255]
        return '#%02x%02x%02x' % (levels[n // 36], levels[n // 6 % 6], levels[n % 6])
    gray = 8 + 10 * (n - 232)
    return '#%02x%02x%02x' % (gray, gray, gray)


class Cell:
    __slots__ = ('data', 'fg', 'bg', 'bold', 'underscore', 'reverse')

    def __init__(self, data, style):
        self.data = data
        self.fg, self.bg, self.bold, self.underscore, self.reverse = style


PLAIN = (None, None, False, False, False)


class Screen:
    """The cells a terminal would show after the bytes fed so far."""

    def __init__(self, columns, lines):
        self.columns, self.lines = columns, lines
        self.cells = self.blank_rows(lines, PLAIN)
        self.x = self.y = 0
        # The last column is written and the next character starts a line. As in xterm the
        # cursor stays on that column meanwhile, so erasing to the end of the line takes it.
        self.wrap = False
        self.style = PLAIN
        self.kept = None  # the main screen and its cursor while the alternate one is shown
        self.cursor = (0, 0)
        self.decoder = codecs.getincrementaldecoder('utf-8')('replace')
        self.state = 'text'
        self.sequence = ''

    def blank_rows(self, count, style):
        erased = (None, style[1], False, False, False)
        return [[Cell(' ', erased) for _ in range(self.columns)] for _ in range(count)]

    @property
    def display(self):
        return [''.join(cell.data for cell in row) for row in self.cells]

    def resize(self, lines, columns):
        rows = [row[:columns] + [Cell(' ', PLAIN) for _ in range(columns - len(row))]
                for row in self.cells[:lines]]
        self.columns, self.lines = columns, lines
        self.cells = rows + self.blank_rows(lines - len(rows), PLAIN)
        self.x, self.y = min(self.x, columns - 1), min(self.y, lines - 1)
        self.wrap = False

    def feed(self, data):
        for ch in self.decoder.decode(data):
            getattr(self, 'in_' + self.state)(ch)

    def in_text(self, ch):
        if ch == '\x1b':
            self.state = 'escape'
        elif ch == '\r':
            self.x, self.wrap = 0, False
        elif ch in '\n\v\f':
            self.line_feed()
        elif ch == '\b':
            self.x, self.wrap = max(self.x - 1, 0), False
        elif ch == '\t':
            self.x, self.wrap = min(self.x // 8 * 8 + 8, self.columns - 1), False
        elif ch >= ' ' and ch != '\x7f':
            self.put(ch)

    def in_escape(self, ch):
        self.state = 'text'
        if ch == '[':
            self.state, self.sequence = 'csi', ''
        elif ch in ']P_^X':
            self.state = 'string'
        elif ch in '()*+#%':
            self.state = 'skip'
        elif ch == '7':
            self.cursor = (self.x, self.y)
        elif ch == '8':
            self.move(*self.cursor)
        elif ch == 'M':
            self.move(self.x, self.y - 1)
        elif ch == 'c':
            self.__init__(self.columns, self.lines)

    def in_skip(self, ch):
        self.state = 'text'

    def in_string(self, ch):
        if ch == '\a':
            self.state = 'text'
        elif ch == '\x1b':
            self.state = 'string_end'

    def in_string_end(self, ch):
        self.state = 'text' if ch == '\\' else 'string'

    def in_csi(self, ch):
        if '\x40' <= ch <= '\x7e':
            self.state = 'text'
            self.control(self.sequence, ch)
        elif ch == '\x1b':
            self.state = 'escape'
        else:
            self.sequence += ch

    def line_feed(self):
        self.wrap = False
        if self.y + 1 < self.lines:
            self.y += 1
        else:
            self.cells = self.cells[1:] + self.blank_rows(1, self.style)

    def move(self, x, y):
        self.x = min(max(x, 0), self.columns - 1)
        self.y = min(max(y, 0), self.lines - 1)
        self.wrap = False

    def put(self, ch):
        if unicodedata.combining(ch) or unicodedata.category(ch) in ('Mn', 'Me', 'Cf'):
            at = self.x if self.wrap else self.x - 1
            while at > 0 and not self.cells[self.y][at].data:
                at -= 1
            if at >= 0:
                self.cells[self.y][at].data += ch
            return
        width = 2 if unicodedata.east_asian_width(ch) in 'WF' else 1
        if self.wrap or self.x + width > self.columns:
            self.x = 0
            self.line_feed()
        row = self.cells[self.y]
        row[self.x] = Cell(ch, self.style)
        if width == 2:
            row[self.x + 1] = Cell('', self.style)
        if self.x + width < self.columns:
            self.x += width
        else:
            self.x, self.wrap = self.columns - 1, True

    def erase(self, y, start, end):
        self.cells[y][start:end] = self.blank_rows(1, self.style)[0][start:end]

    def control(self, sequence, final):
        private = sequence[:1] in ('?', '>', '<', '=')
        numbers = [int(part) if part.isdigit() else 0
                   for part in sequence.lstrip('?><=').replace(':', ';').split(';')]
        first = numbers[0]
        count = first or 1
        if final in 'hl':
            if private and first in (47, 1047, 1049):
                self.alternate(final == 'h')
        elif private or sequence[-1:] in (' ', '!', '"', '$', "'"):
            return
        elif final in 'Hf':
            self.move((numbers[1] if len(numbers) > 1 else 1) - 1, first - 1)
        elif final == 'A':
            self.move(self.x, self.y - count)
        elif final in 'Be':
            self.move(self.x, self.y + count)
        elif final in 'Ca':
            self.move(self.x + count, self.y)
        elif final == 'D':
            self.move(self.x - count, self.y)
        elif final == 'E':
            self.move(0, self.y + count)
        elif final == 'F':
            self.move(0, self.y - count)
        elif final in 'G`':
            self.move(count - 1, self.y)
        elif final == 'd':
            self.move(self.x, count - 1)
        elif final == 'J':
            if first == 0:
                self.erase(self.y, self.x, self.columns)
                rows = range(self.y + 1, self.lines)
            elif first == 1:
                self.erase(self.y, 0, self.x + 1)
                rows = range(self.y)
            else:
                rows = range(self.lines)
            for y in rows:
                self.erase(y, 0, self.columns)
        elif final == 'K':
            start, end = [(self.x, self.columns), (0, self.x + 1), (0, self.columns)][min(first, 2)]
            self.erase(self.y, start, end)
        elif final == 'X':
            self.erase(self.y, self.x, min(self.x + count, self.columns))
        elif final in 'P@':
            row = self.cells[self.y]
            blanks = self.blank_rows(1, self.style)[0][:min(count, self.columns - self.x)]
            if final == 'P':
                row[self.x:] = row[self.x + len(blanks):] + blanks
            else:
                row[self.x:] = blanks + row[self.x:self.columns - len(blanks)]
        elif final in 'LM':
            count = min(count, self.lines - self.y)
            below = self.cells[self.y:]
            blanks = self.blank_rows(count, self.style)
            below = blanks + below[:len(below) - count] if final == 'L' else below[count:] + blanks
            self.cells[self.y:] = below
        elif final in 'ST':
            count = min(count, self.lines)
            blanks = self.blank_rows(count, self.style)
            if final == 'S':
                self.cells = self.cells[count:] + blanks
            else:
                self.cells = blanks + self.cells[:self.lines - count]
        elif final == 's':
            self.cursor = (self.x, self.y)
        elif final == 'u':
            self.move(*self.cursor)
        elif final == 'm':
            self.attributes(numbers)

    def alternate(self, on):
        if on and self.kept is None:
            self.kept = (self.cells, self.x, self.y)
            self.cells = self.blank_rows(self.lines, PLAIN)
            self.move(0, 0)
        elif not on and self.kept is not None:
            cells, x, y = self.kept
            self.kept = None
            self.cells = self.blank_rows(self.lines, PLAIN)
            for row, old in zip(self.cells, cells):
                row[:len(old)] = old[:self.columns]
            self.move(x, y)

    def attributes(self, numbers):
        fg, bg, bold, underscore, reverse = self.style
        i = 0
        while i < len(numbers):
            n = numbers[i]
            i += 1
            if n == 0:
                fg, bg, bold, underscore, reverse = PLAIN
            elif n == 1:
                bold = True
            elif n == 4:
                underscore = True
            elif n == 7:
                reverse = True
            elif n in (21, 22):
                bold = False
            elif n == 24:
                underscore = False
            elif n == 27:
                reverse = False
            elif 30 <= n <= 37:
                fg = PALETTE[n - 30]
            elif 40 <= n <= 47:
                bg = PALETTE[n - 40]
            elif 90 <= n <= 97:
                fg = PALETTE[n - 82]
            elif 100 <= n <= 107:
                bg = PALETTE[n - 92]
            elif n == 39:
                fg = None
            elif n == 49:
                bg = None
            elif n in (38, 48):
                color = None
                if numbers[i:i + 1] == [5] and len(numbers) > i + 1:
                    color = indexed_color(min(numbers[i + 1], 255))
                    i += 2
                elif numbers[i:i + 1] == [2] and len(numbers) > i + 3:
                    color = '#%02x%02x%02x' % tuple(min(v, 255) for v in numbers[i + 1:i + 4])
                    i += 4
                else:
                    break
                if n == 38:
                    fg = color
                else:
                    bg = color
        self.style = (fg, bg, bold, underscore, reverse)


def page_of(screen, title, font):
    rows = []
    for y in range(screen.lines):
        runs = []
        for cell in screen.cells[y]:
            fg, bg = cell.fg or FOREGROUND, cell.bg or BACKGROUND
            if cell.reverse:
                fg, bg = bg, fg
            style = (fg, bg, cell.bold, cell.underscore)
            if not runs or runs[-1][0] != style:
                runs.append((style, []))
            runs[-1][1].append(cell.data)
        spans = []
        for (fg, bg, bold, underline), text in runs:
            css = f'color:{fg}'
            if bg != BACKGROUND:
                css += f';background:{bg}'
            if bold:
                css += ';font-weight:700'
            if underline:
                css += ';text-decoration:underline'
            spans.append(f'<span style="{css}">{html.escape("".join(text))}</span>')
        rows.append('<div class="r">' + ''.join(spans) + '</div>')

    face, family = '', 'ui-monospace,Menlo,Consolas,monospace'
    if font:
        url = 'file://' + os.path.abspath(font)
        face = ''.join(f"@font-face{{font-family:shot;font-weight:{weight};src:url('{url}')}}"
                       for weight in (400, 700))
        family = 'shot,' + family
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>
{face}
body{{margin:0;background:{BACKGROUND}}}
.win{{display:inline-block;background:{BACKGROUND};color:{FOREGROUND};font-family:{family};\
font-size:{FONT_PX}px;line-height:{LINE_PX}px}}
.bar{{height:{BAR_PX}px;display:flex;align-items:center;justify-content:center;\
background:#161b22;color:#7d8590;border-bottom:1px solid #21262d}}
.scr{{padding:{PAD_TOP}px {PAD_X}px {PAD_BOTTOM}px;white-space:pre}}
.r{{height:{LINE_PX}px}}
</style></head><body><div class="win"><div class="bar">{html.escape(title)}</div>\
<div class="scr">{"".join(rows)}</div></div></body></html>"""


def find_browser(given):
    for name in [given] if given else BROWSERS:
        path = shutil.which(name) or (name if os.path.isfile(name) else None)
        if path:
            return path
    return None


def render_png(browser, page, png, columns, lines):
    width = 2 * PAD_X + math.ceil(CELL_PX * columns) + 2
    height = BAR_PX + 1 + PAD_TOP + PAD_BOTTOM + LINE_PX * lines
    with tempfile.TemporaryDirectory() as profile:
        subprocess.run(
            [browser, '--headless=new', '--disable-gpu', '--no-first-run', '--hide-scrollbars',
             f'--user-data-dir={profile}', '--force-device-scale-factor=1',
             f'--window-size={width},{height}', f'--screenshot={os.path.abspath(png)}',
             'file://' + os.path.abspath(page)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120, check=False)
    return os.path.exists(png)


def position(text):
    column, _, row = text.partition('x')
    return int(column), int(row)


def parse_steps(text, columns, lines):
    """Gives (kind, value, step) for each step; value is what the step sends, waits or names.

    Raises ValueError with the step that cannot be read.
    """
    steps = []
    for step in (part.strip() for part in text.replace('\n', ',').split(',')):
        if not step:
            continue
        kind, _, value = step.partition(':')
        try:
            if kind == 'sleep':
                value = float(value)
            elif kind == 'key':
                value = (KEYS.get(value.lower()) or {1: value}[len(value)]).encode()
            elif kind == 'text':
                value = value.encode()
            elif kind == 'click':
                column, row = position(value)
                value = f'\x1b[<0;{column + 1};{row + 1}M\x1b[<0;{column + 1};{row + 1}m'.encode()
            elif kind == 'wheel':
                direction, _, where = value.partition(':')
                button = {'up': 64, 'down': 65}[direction]
                column, row = position(where) if where else (columns // 2, lines // 2)
                value = f'\x1b[<{button};{column + 1};{row + 1}M'.encode()
            elif kind == 'resize':
                value = position(value)
            elif kind != 'shot' or not value:
                raise ValueError
        except (ValueError, KeyError):
            raise ValueError(step) from None
        steps.append((kind, value, step))
    return steps


def main():
    usage = __doc__.split('\n\n')[1].removeprefix('usage: ')
    parser = argparse.ArgumentParser(usage=usage, add_help=False)
    parser.add_argument('-h', '--help', action='store_true')
    parser.add_argument('--cols', type=int, default=174)
    parser.add_argument('--rows', type=int, default=44)
    parser.add_argument('--steps', default='sleep:2')
    parser.add_argument('--text')
    parser.add_argument('--html')
    parser.add_argument('--png')
    parser.add_argument('--title')
    parser.add_argument('--font')
    parser.add_argument('--env', action='append', default=[])
    parser.add_argument('--chrome')
    parser.add_argument('--raw')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.help:
        print(__doc__, end='')
        return 0
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('a command must follow --')
    try:
        steps = parse_steps(args.steps, args.cols, args.rows)
    except ValueError as error:
        parser.error(f'cannot read the step {error}')

    browser = find_browser(args.chrome) if args.png else None
    if args.png and not browser:
        print('tuishot: no Chrome or Chromium found; the image is left out', file=sys.stderr)

    env = dict(os.environ, TERM='xterm-256color', COLORTERM='truecolor')
    env.pop('NO_COLOR', None)
    for setting in args.env:
        name, equals, value = setting.partition('=')
        if equals:
            env[name] = value
        else:
            env.pop(name, None)

    screen = Screen(args.cols, args.rows)

    raw = open(args.raw, 'wb') if args.raw else None
    pid, tty = pty.fork()
    if pid == 0:
        try:
            os.execvpe(command[0], command, env)
        except OSError as error:
            print(f'tuishot: {command[0]}: {error.strerror}', file=sys.stderr)
            os._exit(127)

    def resize(columns, lines):
        fcntl.ioctl(tty, termios.TIOCSWINSZ, struct.pack('HHHH', lines, columns, 0, 0))
        os.kill(pid, signal.SIGWINCH)

    def pump(seconds):
        """Feeds the program's output to the screen; false once the program is gone."""
        end = time.monotonic() + seconds
        while (left := end - time.monotonic()) > 0:
            if not select.select([tty], [], [], left)[0]:
                continue
            try:
                data = os.read(tty, 65536)
            except OSError:
                return False
            if not data:
                return False
            screen.feed(data)
            if raw:
                raw.write(data)
        return True

    def send(data, settle):
        os.write(tty, data)
        return pump(settle)

    def save(suffix=''):
        def named(path):
            if not path or not suffix:
                return path
            base, extension = os.path.splitext(path)
            return f'{base}-{suffix}{extension}'

        if args.text:
            with open(named(args.text), 'w', encoding='utf-8') as out:
                out.write('\n'.join(line.rstrip() for line in screen.display) + '\n')
        page = named(args.html)
        if not page and args.png:
            page = os.path.splitext(named(args.png))[0] + '.html'
        if page:
            with open(page, 'w', encoding='utf-8') as out:
                out.write(page_of(screen, args.title or ' '.join(command), args.font))
        if browser:
            if not render_png(browser, page, named(args.png), screen.columns, screen.lines):
                print(f'tuishot: {browser} wrote no image', file=sys.stderr)

    resize(args.cols, args.rows)
    alive = pump(0.3)
    saved = False
    done = 0
    for kind, value, _ in steps:
        if not alive:
            break
        if kind == 'sleep':
            alive = pump(value)
        elif kind == 'resize':
            screen.resize(value[1], value[0])
            resize(*value)
            alive = pump(0.4)
        elif kind == 'shot':
            save(value)
            saved = True
        else:
            alive = send(value, 0.15)
        done += 1
    if not saved:
        save()

    try:
        os.kill(pid, signal.SIGTERM)
        pump(0.3)
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass
    if raw:
        raw.close()

    if done < len(steps):
        print(f'tuishot: the program ended before step {done + 1}, {steps[done][2]}',
              file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
