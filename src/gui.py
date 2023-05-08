import itertools
import math
import string
import sys
import tkinter as tk
import traceback
from typing import Callable

import PySimpleGUI

import filehash

import PySimpleGUI as sg
import sql_db

import cProfile as profile
import pstats

from intervaltree import Interval, IntervalTree

from match_sets import MatchSet, MatchSetFamily

from exefile import ELFThunks
import entropy

import util

font_name = 'Fira Code'
font_size = 12

def my_log(x: int, max_value=1000, pixel_height=200) -> int:
    return int(math.log(x + 1) / math.log(max_value) * pixel_height)


def visible_to_canvas(x1, x2) -> bool:
    return x2 > 0 and x1 < 10000


class ToolTip:
    """ Create a tooltip for a given widget

    (inspired by https://stackoverflow.com/a/36221216)
    """

    def __init__(self, widget: tk.Widget, text, timeout=1000):
        self.widget = widget
        self.text = text
        self.timeout = timeout
        #self.wraplength = wraplength if wraplength else widget.winfo_screenwidth() // 2
        self.tipwindow = None
        self.id = None
        self.x = self.y = 0
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)
        self.widget.bind("<ButtonPress>", self.leave)

    def enter(self, event=None):
        self.schedule()

    def leave(self, event=None):
        self.unschedule()
        self.hidetip()

    def schedule(self):
        self.unschedule()
        self.id = self.widget.after(self.timeout, self.showtip)

    def unschedule(self):
        if self.id:
            self.widget.after_cancel(self.id)
        self.id = None

    def showtip(self):
        if self.tipwindow:
            return
        #x = self.widget.winfo_rootx() + 20
        #y = self.widget.winfo_rooty() + self.widget.winfo_height() + 1
        x = self.widget.winfo_pointerx() + 20
        y = self.widget.winfo_pointery() + 2
        self.tipwindow = tk.Toplevel(self.widget)
        self.tipwindow.wm_overrideredirect(True)
        self.tipwindow.wm_geometry("+%d+%d" % (x, y))
        label = tk.Label(self.tipwindow, text=self.text, justify=tk.LEFT,
                         background="#ffffe0", relief=tk.SOLID, borderwidth=1)
        label.pack()

    def hidetip(self):
        if self.tipwindow:
            self.tipwindow.destroy()
        self.tipwindow = None


class MatchHistogram:
    """
    MatchHistogram represents match counts and match sets for a search of a particular file against a single
    database.  In the future, this may support drawing the match scales for multiple databases (e.g. if you
    search both a known-good database vs. a known-malware database).

    This class is responsible for drawing the log-scale match count graph and colorizing the largest match sets.
    """

    def __init__(self,
                 fid_lookup: Callable[[int], sql_db.FileRecord],
                 cumulative_counts: list[sql_db.OffsetCount],
                 match_sets: list[MatchSet],
                 group_family_limit = 100,
                 group_family_threshold = 0.85):

        self.fid_lookup = fid_lookup
        self.cumulative_counts = cumulative_counts
        self.match_sets = match_sets
        self.group_family_limit = group_family_limit
        self.group_family_threshold = group_family_threshold

        self.match_set_families: list[MatchSetFamily] = []
        self.match_set_colors = self.determine_match_set_colors()

        self.offset_count_intervals = IntervalTree()

        self.filter_x1 = 0
        self.filter_x2 = 0
        self.filtered_counts = []

        for oc in self.cumulative_counts:
            if not oc.length:
                continue
            self.offset_count_intervals[oc.offset:oc.offset + oc.length] = oc

    def get_offset_count(self, file_offset) -> sql_db.OffsetCount | None:
        if self.offset_count_intervals:
            interval: set[Interval] = self.offset_count_intervals.at(file_offset)
            if interval:
                return sorted(interval)[0].data


    def filter_cumulative_counts(self, file_to_canvas_offset):
        last_x1 = -1
        self.filtered_counts = []
        for oc in self.cumulative_counts:
            canvas_x1 = file_to_canvas_offset(oc.offset)
            canvas_x2 = file_to_canvas_offset(oc.offset + oc.length)

            if not visible_to_canvas(canvas_x1, canvas_x2):
                continue

            if canvas_x2 == last_x1:
                continue

            self.filtered_counts.append(oc)

            last_x1 = canvas_x1

        # print(f'Filtered from {len(self.cumulative_counts)} to {len(self.filtered_counts)}')
        return self.filtered_counts

    def draw_file_sets(self,
                       graph: sg.Graph,
                       file_to_canvas_offset,
                       y_offset = 0, y_height=200):
        if not self.cumulative_counts:
            return

        for oc in self.filter_cumulative_counts(file_to_canvas_offset):
            canvas_x1 = file_to_canvas_offset(oc.offset)
            canvas_x2 = file_to_canvas_offset(oc.offset + oc.length)

            if canvas_x2 < 0:
                continue
            if canvas_x1 > 10000:
                continue

            fs = oc.get_frozen_set()

            count = oc.get_count()
            height = my_log(count, pixel_height=y_height)

            fill_color = self.match_set_colors.get(fs, 'green')

            graph.draw_rectangle((canvas_x1, height+y_offset),
                                 (canvas_x2, y_offset),
                                 fill_color=fill_color,
                                 line_width=0)

    def determine_match_set_colors(self):
        color_families = [
            [f'{base_color}{n}' for n in range(1, 4)] for base_color in
            ['RoyalBlue', 'SkyBlue', 'LemonChiffon', 'Pink',
             #'tan',
             #'wheat',
             'orange',
             'OrangeRed', 'VioletRed', 'SpringGreen', 'HotPink', 'Goldenrod']
        ]

        match_set_colors = {}

        for color_family, family in zip(color_families, self.group_families()):
            family.first.color = color_family[0]
            remaining_colors = color_family[1:]
            for i, member in enumerate(family.members[1:]):
                member.color = remaining_colors[i % len(remaining_colors)]
            for member in family.members:
                match_set_colors[member.file_set] = member.color

        return match_set_colors

    def group_families(self) -> list[MatchSetFamily]:
        """
        If we did an all-to-all comparison, the quadratic complexity could be slow.  So we use self.group_family_limit
        to keep one of the numbers constant to effectively have linear complexity.
        """
        if self.match_set_families:
            return self.match_set_families

        print(f'Grouping {len(self.match_sets)} match sets')

        '''
        for ms in self.match_sets:
            if ms.family:
                continue

            family = MatchSetFamily(ms)
            self.match_set_families.append(family)

            for other in self.match_sets:
                if other.family:
                    continue
                if ms.similarity(other) > self.group_family_threshold:
                    family.add(other)

            if len(self.match_set_families) >= self.group_family_limit:
                break
        '''

        # Match sets are sorted by most-bytes-first.
        # TODO: consider clustering algorithms.  Set comparisons have arbitrarily high dimensionality, so picking
        # a good algorithm may be tricky.
        for ms in self.match_sets:
            if self.match_set_families:
                family_scores = []
                for family in self.match_set_families:
                    similarity = family.first.similarity(ms)
                    family_scores.append((similarity, family))
                highest_score, highest_family = sorted(family_scores, key=lambda x:-x[0])[0]
                if highest_score > self.group_family_threshold:
                    highest_family.add(ms)
                    continue
            if len(self.match_set_families) < self.group_family_limit:
                self.match_set_families.append(MatchSetFamily(ms))

        self.match_set_families = sorted(self.match_set_families, key=lambda ms:-ms.total_bytes())

        return self.match_set_families

    def format_set(self, file_set, max1=10, max2=50,
                  byte_match_count = None,
                  total_bytes = None,
                  hide_if_over = True):
        if not file_set:
            return

        if len(file_set) >= max2 and hide_if_over:
            return


        show_path = len(file_set) < max1
        if hide_if_over and max1 >= max2:
            show_path = True


        def file_txt(fid):
            if show_path:
                s = self.fid_lookup(fid).path
            else:
                s = self.fid_lookup(fid).name
            if byte_match_count and fid in byte_match_count:
                byte_match = byte_match_count[fid]
                prct = byte_match * 100 / total_bytes
                s = f'{s} ({prct:0.1f}%)'

            return s

        joinchar = '\n' if show_path else ' '

        fid_txt_count = [(file_txt(fid), (byte_match_count or {}).get(fid, None)) for fid in file_set]
        if byte_match_count:
            # sort by descending byte count
            fid_txt_count = sorted(fid_txt_count, key=lambda x: -(x[1] or 0))
        else:
            fid_txt_count = sorted(fid_txt_count, key=lambda x: x[0])
        if not hide_if_over:
            fid_txt_count = fid_txt_count[:max1]

        file_txts = [f_text for f_text, match_count in fid_txt_count]
        return joinchar.join(file_txts)

    def print_set(self, txt: sg.MLine, file_set, max1=10, max2=50, text_color=None,
                  byte_match_count=None,
                  total_bytes=None,
                  bgcolor=None):
        msg = self.format_set(file_set, max1, max2, byte_match_count, total_bytes)
        if msg:
            txt.print(msg, font=(font_name, font_size), text_color=text_color, background_color=bgcolor)

    def describe_match_sets(self, txt: sg.MLine):
        families = self.group_families()
        for index, family in enumerate(families):
            #if not family.first.color:
            #    continue

            total_bytes = family.total_bytes()

            bytes_txt = f'{total_bytes}B' if total_bytes < 10000 else f'{total_bytes//1024}KB'

            union_files = family.union_file_set()
            intersect_files = family.intersection_file_set()

            first_set = family.first_file_set()

            lengths = f' File counts: {len(first_set)} first, {len(union_files)} union, {len(intersect_files)} intersect'

            description = f'Match Set Family {index}: {bytes_txt:5} {len(family.members)} sets {lengths}'
            bgcolor = (family.first.color or ('white' if index%2 else 'grey50'))
            txt.print(description, background_color=bgcolor, text_color='black')

            max1 = 2
            max2 = 20
            self.print_set(txt, intersect_files, max1, max2, text_color='black', bgcolor=bgcolor)

            extra_fids = union_files - intersect_files
            max1 = max(max1 - len(intersect_files), 1)
            max2 = max(max2-len(intersect_files), 2)

            match_bytes = family.count_match_bytes(extra_fids)
            #match_bytes = sorted(match_bytes, key=lambda x:-x[1]) # sort by number of bytes descending

            self.print_set(txt, extra_fids, max1=max1, max2=max2, text_color='grey24',
                           byte_match_count=dict(match_bytes),
                           total_bytes=total_bytes,
                           bgcolor=bgcolor)

            ranges = family.all_ranges()
            if ranges:
                txt_start = '1 range:' if len(ranges) == 1 else f'{len(ranges)} ranges:'
                range_text = txt_start + ' '.join([f'{lo:x}+{hi-lo:x}' for lo, hi in ranges[:20]])
                txt.print(range_text, font=(font_name, font_size), text_color='black', background_color=bgcolor)

class FileView:
    """
    A FileView class is responsible for drawing information about a single file.  This may include:

    1. A MatchHistogram.  In the future, we may support multiple.
    2. The raw bytes of the file, as well as the zero-ized version of the file.
    3. Known ranges/intervals, as parsed an input by analysis tools.
    """

    def __init__(self, path, data, graph_name):
        assert(isinstance(path, str))

        self.path = path
        self.graph_name = graph_name

        if data:
            self.contents = data
        else:
            with open(path, 'rb') as fd:
                self.contents = fd.read()

        self.elf_thunks = ELFThunks(self.contents)

        self.zeroized_file = filehash.MemFile(path, self.contents, True).data

        # self.values is updated when GUIView reads the event loop
        self.values = {self.graph_name: (0, 0)}
        self.hover_x = 0
        self.file_x = 0
        self.hover_y = 0
        self.hover_line = None

        self.last_graph_size = None

        width, height = sg.Window.get_screen_size()
        self.canvas_coord_width = 10000
        self.canvas_coord_height = 800
        initial_canvas_size = (width * 80 // 100, 800)
        self.graph = sg.Graph(initial_canvas_size,
                              (0, 0), (self.canvas_coord_width, self.canvas_coord_height),
                              background_color='grey', key=graph_name)

        self.file_x_start = 0
        self.file_x_end = len(self.contents)

        self.drag_start_x = None
        self.drag_start_x_file = None

        self.match_histogram: MatchHistogram | None = None

        self.label_intervals = [(0, len(self.contents), f'File {path}')]
        for thunk in self.elf_thunks.thunks:
            for a_range, b_range, meta in sorted(thunk.all(), key=lambda x:x[0]):
                a_begin, a_len = a_range
                a_end = a_begin + a_len

                self.label_intervals.append((a_begin, a_len, meta['name']))

        self.label_interval_tree = IntervalTree()

        for i, data in enumerate(self.label_intervals):
            file_begin, file_len, txt = data

            self.label_interval_tree[file_begin:file_begin+(file_len or 1)] = (i, file_begin, file_len, txt)

        self.histogram_y = self.canvas_coord_height - 350

    def draw_interval(self, y, x1, x2, txt):

        height = 20
        if x2 == x1:
            self.graph.draw_line((x1, y - height), (x1, y), width=3)
        else:
            self.graph.draw_line((x1, y-height), (x1, y), width=3)
            self.graph.draw_line((x1, y), (x2, y), width=3)
            self.graph.draw_line((x2, y-height), (x2, y), width=3)

        if x2 - x1 > 50:
            self.graph.draw_text(txt, ((x1+x2)//2, y-30), font=(10,))

    def draw_intervals(self):
        level_maximums = [0]*9
        level_x1s = [0]*9

        file_x1 = self.canvas_to_file_offset(0)
        file_x2 = self.canvas_to_file_offset(10000)
        intervals = self.label_interval_tree.overlap(file_x1, file_x2)
        intervals = sorted((i.data for i in intervals), key=lambda x:x[0])
        #for file_begin, file_len, txt in self.label_intervals:
        print(f'There are {len(intervals)} of {len(self.label_intervals)} intervals')
        for i, file_begin, file_len, txt in intervals:
            file_end = file_begin + file_len

            maximums = ' '.join(f"{lm:6x}" for lm in level_maximums)
            for level, level_max in enumerate(level_maximums):
                if file_begin >= level_max:
                    x1 = self.file_to_canvas_offset(file_begin)
                    x2 = self.file_to_canvas_offset(file_end)

                    if x2 == level_x1s[level]:
                        continue

                    level_maximums[level] = file_end
                    level_x1s[level] = x1

                    if x2 < 0:
                        continue
                    #if x1 > 10000:
                    #    continue

                    y = self.histogram_y - 60*level
                    self.draw_interval(y, x1, x2, txt)
                    break

    def canvas_to_file_offset(self, x: int) -> int:
        file_view_width = self.file_x_end - self.file_x_start

        return ((x or 0) * file_view_width // self.canvas_coord_width) + self.file_x_start

    def file_to_canvas_offset(self, file_offset: int) -> int:
        file_view_width = self.file_x_end - self.file_x_start
        return (file_offset - self.file_x_start) * self.canvas_coord_width // file_view_width

    def get_hover_file_offset(self):
        #if self.hover_x is None:
        #    return None
        # return self.canvas_to_file_offset(self.hover_x)
        return self.file_x

    def update_hover_line(self):
        if self.hover_line is not None:
            self.graph.delete_figure(self.hover_line)

        # Do the conversion to snap to an offset
        x = self.file_to_canvas_offset(self.canvas_to_file_offset(self.hover_x))

        self.hover_line = self.graph.draw_line((x, 0), (x, self.canvas_coord_height), color='white')

    def redraw_graph(self):
        self.graph.erase()
        self.update_hover_line()
        if self.match_histogram:
            y_offset = self.histogram_y
            self.match_histogram.draw_file_sets(self.graph, self.file_to_canvas_offset, y_offset, 300)
        self.draw_intervals()

    def adjust_sizes(self, width, height):
        wh = (width, height)
        if self.last_graph_size == wh:
            return
        print(f'Adjusting size {wh} {self.last_graph_size}')
        self.last_graph_size = wh
        self.graph.set_size(wh)
        self.redraw_graph()

    def set_counts(self,
                   fid_lookup,
                   cumulative_counts: list[sql_db.OffsetCount],
                   match_sets):

        self.match_histogram = MatchHistogram(fid_lookup, cumulative_counts, match_sets)

    def clip_zoom(self):
        overshoot = len(self.contents) // 20

        if self.file_x_start < -overshoot:
            self.file_x_start = -overshoot
        if self.file_x_end > len(self.contents) + overshoot:
            self.file_x_end = len(self.contents) + overshoot


    def handle_mouse_wheel(self):
        # print(f"Mouse {self.graph.user_bind_event.delta}")
        mouse_steps = int(self.graph.user_bind_event.delta / 120)
        file_range = self.file_x_end - self.file_x_start
        if mouse_steps < 0:
            # Zoom out
            self.file_x_start -= file_range // 5
            self.file_x_end += file_range // 5

        else:
            # Zoom in
            file_hover_x = self.get_hover_file_offset()
            left = file_hover_x - self.file_x_start
            right = self.file_x_end - file_hover_x
            self.file_x_start += left // 5
            self.file_x_end -= right // 5

        self.clip_zoom()

        self.redraw_graph()

    def update_hover(self):
        self.hover_x, self.hover_y = self.values[self.graph_name]
        self.file_x = self.canvas_to_file_offset(self.hover_x)

    def action_click(self):
        x, y = self.values[self.graph_name]
        self.drag_start_x = x
        self.drag_start_x_file = self.canvas_to_file_offset(self.drag_start_x)

    def _do_drag(self, delta):
        self.file_x_start += delta
        self.file_x_end += delta

        self.clip_zoom()

        self.redraw_graph()

    def action_drag(self):
        x, y = self.values[self.graph_name]
        file_x = self.canvas_to_file_offset(x)
        delta_x = self.drag_start_x_file - file_x

        self.hover_x = x
        self._do_drag(delta_x)

    def zoom_to(self, file_x_offset):
        zoom_range = self.file_x_end - self.file_x_start
        if not (self.file_x_start < file_x_offset < self.file_x_end):
            self._do_drag(file_x_offset - self.file_x_start - (zoom_range//2))

        self.hover_x = self.file_to_canvas_offset(file_x_offset)

        self.file_x = file_x_offset
        # TODO: scroll if needed

        self.update_hover_line()


    def get_events(self):
        return [
            (self.graph, '<Motion>', self.update_hover),
            (self.graph, '<MouseWheel>', self.handle_mouse_wheel),
            (self.graph, '<Button-1>', self.action_click),
            (self.graph, '<B1-Motion>', self.action_drag),
        ]


class GUIView:
    """
    GUIView is a high-level representation of the REveal graphical interface.  It renders a window with a top FileView
    object and a bottom text box.
    """

    def __init__(self, file_path, file_bytes=None):
        self.view1 = FileView(file_path, file_bytes, 'view1')

        screen_width, screen_height = sg.Window.get_screen_size()


        self.bottom_text = sg.MLine("Bottom text",
                                    size=(100, 30),
                                    font=(font_name, font_size),
                                    background_color='grey',
                                    text_color='white',
                                    no_scrollbar=True,
                                    key='-BYTES-')

        self.bottom_text2 = sg.MLine("Bottom text",
                                     size=(100, 30),
                                     font=(font_name, font_size),
                                     background_color='grey',
                                     text_color='white',
                                     no_scrollbar=False,
                                     key='-BYTES-')

        layout = [
            [self.view1.graph],
            [self.bottom_text, self.bottom_text2]
        ]

        self.window = sg.Window(f'Sector Hash {file_path}',
                                layout,
                                location=(screen_width * 1 // 10, screen_height * 1 // 10),
                                finalize=True,
                                resizable=True,
                                background_color='light grey')
        self.window.refresh()

        self.tt: ToolTip | None = None

    def set_counts(self,
                   fid_lookup,
                   cumulative_counts: list[sql_db.OffsetCount],
                   match_sets):
        self.view1.set_counts(fid_lookup, cumulative_counts, match_sets)

    def adjust_sizes(self):
        window_inner_width = self.window.size[0] - 30
        window_inner_height = self.window.size[1] - 30
        self.view1.adjust_sizes(window_inner_width, 300)

        txt_width = window_inner_width // 10 // 2

        canvas_width, canvas_height = self.view1.graph.get_size()

        screen_width, screen_height = sg.Window.get_screen_size()

        #txt_lines = (window_inner_height - canvas_height)//20
        txt_lines = (screen_height * 8 // 10 - canvas_height)//20
        txt_lines = max(txt_lines, 4)
        # print(f'lines = {window_inner_height} {self.view1.canvas_coord_height} {self.view1.graph.get_size()} {txt_width} {txt_lines}')

        txt_size = (txt_width, txt_lines)

        self.bottom_text.Size = txt_size
        self.bottom_text.set_size(txt_size)

        self.bottom_text2.Size = txt_size
        self.bottom_text2.set_size((txt_width-2, txt_lines))

    def add_matches(self, txt: sg.MLine, view: FileView, file_offset):
        oc = view.match_histogram.get_offset_count(file_offset) if view.match_histogram else None

        txt_width, txt_height = txt.Size

        max_lines = 500

        if oc:
            txt.print(f'Matches {oc.fileCount} files and {oc.hashCount} by simple count')

            fs = oc.get_frozen_set()
            if fs:
                txt.print(f'Matches {len(fs)} files by set count', font=(font_name, font_size, 'bold'))
                files = [view.match_histogram.fid_lookup(fid) for fid in fs]
                files = [f for f in files if f]
                files: list[sql_db.FileRecord]

                if len(files) > max_lines:
                    fnames = sorted([file.name for file in files])
                    txt.print(' '.join(sorted(fnames)[:50]), font=(font_name, font_size-1))
                else:
                    paths = sorted([file.path for file in files])
                    path_txt = '\n'.join(paths)
                    txt.print(path_txt, font=(font_name, font_size-1))

    def add_entropy(self, txt: sg.MLine, file_bytes: bytes):
        entropies = []

        if not file_bytes:
            return

        entropies.append(('Byte', entropy.entropy(file_bytes)))

        if len(file_bytes) % 8 == 0:
            entropies.append(('Word', entropy.word_entropy(file_bytes)))
            entropies.append(('Dword', entropy.dword_entropy(file_bytes)))
            entropies.append(('Qword', entropy.qword_entropy(file_bytes)))

        entropies.append(('NibLo', entropy.nib_entropy_lo(file_bytes)))
        entropies.append(('NibHi', entropy.nib_entropy_hi(file_bytes)))

        value = '  '.join(f'{name} {value:5.3f}' for name, value in entropies)
        txt.print(f'Entropy {value}')

    def add_hexdump(self,
                    txt: sg.MLine,
                    view: FileView,
                    file_offset: int):
        txt_width, txt_height = txt.Size

        # Two hex bytes plus one ASCII byte per raw byte
        max_columns = (txt_width - font_size) // 3
        byte_columns = (max_columns // 8) * 8
        byte_rows = 8

        total_bytes = byte_columns * byte_rows
        file_bytes = view.contents[file_offset:file_offset + total_bytes]

        lines = []

        line_data = []
        line_offset = 0

        printable_chars = set(ord(i) for i in string.printable if i not in string.whitespace)
        for offset in range(0, len(file_bytes)):
            full_offset = file_offset + offset
            if offset and offset % byte_columns == 0:
                lines.append((line_offset, line_data))
                line_data = []
                line_offset = offset

            file_bytes = view.contents[full_offset:full_offset + 1]
            z_bytes = view.zeroized_file[full_offset:full_offset + 1]

            line_data.append((file_bytes, z_bytes))

        if line_data:
            lines.append((line_offset, line_data))

        for line_offset, line_data in lines:
            full_offset = file_offset + line_offset

            txt.print(f'{full_offset:6x}: ', end='')

            # here we try to minimize the number of calls to sg.MLine.print by grouping similar items together
            line_groups = []
            fb_accum = b''
            zb_accum = b''
            for file_byte, zero_byte in line_data:
                accum_match = fb_accum == zb_accum
                byte_match = file_byte == zero_byte

                if not fb_accum or accum_match == byte_match:
                    fb_accum += file_byte
                    zb_accum += zero_byte
                else:
                    line_groups.append((fb_accum, zb_accum))
                    fb_accum = file_byte
                    zb_accum = zero_byte
            if fb_accum:
                line_groups.append((fb_accum, zb_accum))


            for file_byte, zero_byte in line_groups:
                if file_byte == zero_byte:
                    txt.print(file_byte.hex(), end='', text_color='black', font=(font_name, font_size))
                else:
                    txt.print(file_byte.hex(), end='', text_color='grey24', font=(font_name, font_size, 'underline'))

            txt.print('  ', end='')
            for file_byte, zero_byte in line_groups:
                ascii = ''.join([chr(b) if b in printable_chars else '.' for b in file_byte])
                if file_byte == zero_byte:
                    txt.print(ascii, end='', font=(font_name, font_size))
                else:
                    txt.print(ascii, end='', text_color='grey30', font=(font_name, font_size, 'underline'))

            txt.print('')

    def update_text(self, txt: sg.MLine, view: FileView, file_offset: int):
        if file_offset is None:
            return

        # txt.update('')
        txt.print(f'File Offset {file_offset:x}  {file_offset // 1024}KB', font=(font_name, font_size, 'bold'))


        if file_offset >= 0:
            # We stuff the current character-column .Size attribute into txt.Size when we update the text display width

            entropy_bytes = view.contents[file_offset:file_offset+512]
            self.add_entropy(txt, entropy_bytes)
            self.add_hexdump(txt, view, file_offset)
            self.add_matches(txt, view, file_offset)

            self.add_thunk_txt(txt, self.view1, file_offset)

    def add_thunk_txt(self, txt: sg.MLine, view: FileView, file_offset: int):
        if view.elf_thunks:
            for thunk in view.elf_thunks.find_thunks(file_offset, only_nearest=False):
                name, translated, thunk_off, meta = thunk
                name_off = f'{name}+0x{thunk_off:x}'
                if name_off is None:
                    name_off = -1
                if translated is None:
                    translated = -1
                txt.print(f'Thunk {name_off:16} {translated:6x}')
                if 'struct' in meta:
                    s = meta['struct']
                    if isinstance(s, dict):
                        for k, v in s.items():
                            if isinstance(v, int):
                                v = f'0x{v:x}'
                            txt.print(f'  {k:12} = {v}', font=(font_name, font_size-1))
                    else:
                        txt.print(str(s), font=(font_name, font_size-1))

    def update_texts(self):
        self.bottom_text.update('')

        file_offset = self.view1.get_hover_file_offset()
        self.update_text(self.bottom_text, self.view1, file_offset)

        #self.add_thunk_txt(self.bottom_text2, self.view1, file_offset)

        self.bottom_text.set_vscroll_position(0)


    def init_texts(self):
        self.bottom_text2.update('')
        self.view1.match_histogram.describe_match_sets(self.bottom_text2)
        self.bottom_text2.set_vscroll_position(0)

    def ishex(self, c):
        return c.lower() in '0123456789abcdef'

    def show_tip(self, text):
        if self.tt:
            self.tt.unschedule()
            self.tt.hidetip()
        self.tt = ToolTip(self.bottom_text2.widget, text, timeout=5)
        self.tt.showtip()

    def expand_hex(self, tktext: tk.Text):
        cur = tktext.index('current')

        row, col = cur.split('.')

        lo = int(col)
        hi = int(col)
        char = tktext.get(f'{row}.{col}')

        if not self.ishex(char):
            return

        while lo > 0:
            char = tktext.get(f'{row}.{lo-1}')
            if not self.ishex(char):
                if char in (string.digits+string.ascii_letters):
                    return
                break
            lo -= 1

        while True:
            char = tktext.get(f'{row}.{hi}')
            if not self.ishex(char):
                if char in (string.digits+string.ascii_letters):
                    return
                break
            hi += 1

        word = tktext.get(f'{row}.{lo}', f'{row}.{hi}')

        return int(word, 16)

    def find_match_family(self, tktext: tk.Text) -> int | None:
        cur = tktext.index('current')
        row, col = cur.split('.')

        row = int(row)
        while row >= 0:
            find_txt = 'Match Set Family '
            begin_line = tktext.get(f'{row}.0', f'{row}.{len(find_txt)}')
            if begin_line == find_txt:
                next_line = tktext.get(f'{row}.{len(find_txt)}', f'{row}.{len(find_txt)+8}')
                match_family_index = int(next_line.split(':')[0])

                return match_family_index

            #print(f'Line begin {begin_line}')
            row -= 1

    def click_text(self):
        offset = self.expand_hex(self.bottom_text2.TKText)

        if offset is not None:
            self.show_tip(f'Hello, world {offset}')
            self.view1.zoom_to(offset)

    def hover_text(self):
        match_family_index = self.find_match_family(self.bottom_text2.TKText)
        if match_family_index is None:
            return

        family = self.view1.match_histogram.match_set_families[match_family_index]
        union_files = family.union_file_set()
        intersect_files = family.intersection_file_set()
        first_set = family.first_file_set()

        max1 = 50
        max2 = 50
        msg = self.view1.match_histogram.format_set(intersect_files, max1, max2)

        extra_files = union_files - intersect_files
        max1 = max(max1 - len(intersect_files), 5)
        max2 = max(max2 - len(intersect_files), 5)

        match_bytes = family.count_match_bytes(extra_files)
        msg2 = self.view1.match_histogram.format_set(extra_files, max1, max2,
                                                     byte_match_count=dict(match_bytes),
                                                     total_bytes=family.total_bytes())

        if msg2:
            msg = f'{msg}\n\n{msg2}'

        self.show_tip(msg)


    def event_loop(self):
        self.adjust_sizes()

        self.init_texts()
        self.window.bind("<Configure>", "+RESIZE+")
        #self.bottom_text2.set_right_click_menu(["Hello", "World"])

        actions = [
            (self.bottom_text2, "<Button-1>", self.click_text),
            (self.bottom_text2, "<Motion>", self.hover_text),
        ]

        event_actions = {}

        action_list =  self.view1.get_events() + actions
        for event_obj, event_name, event_fx in action_list:
            event_name2 = event_name.replace('<', '+').replace('>', '+')

            event_obj.bind(event_name, event_name2)
            event_actions[event_obj.key + event_name2] = event_fx

        while True:
            try:
                event, values = self.window.read()
                if event in ('Quit', None):  # always give ths user a way out
                    break

                if event.startswith(self.view1.graph_name):
                    self.view1.values = values

                with util.Profiler(20):

                    if 'RESIZE' in event:
                        self.adjust_sizes()

                    action = event_actions.get(event, None)
                    if action:
                        action()

                    self.update_texts()

                    self.view1.update_hover_line()


            except Exception as e:
                print(traceback.format_exc())

        self.window.close()

