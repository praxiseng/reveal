import itertools
import math
import string
import sys
import traceback

import filehash

import PySimpleGUI as sg
import sql_db

from intervaltree import Interval, IntervalTree

from exefile import ELFThunks


def my_log(x: int, max_value=1000, pixel_height=200) -> int:
    return int(math.log(x + 1) / math.log(max_value) * pixel_height)


class MatchHistogram:
    """
    MatchHistogram represents match counts and match sets for a search of a particular file against a single
    database.  In the future, this may support drawing the match scales for multiple databases (e.g. if you
    search both a known-good database vs. a known-malware database).

    This class is responsible for drawing the log-scale match count graph and colorizing the largest match sets.
    """

    def __init__(self,
                 fid_name,
                 cumulative_counts: list[sql_db.OffsetCount],
                 match_sets):

        self.cumulative_counts = cumulative_counts
        self.fid_to_name = fid_name

        self.match_set_colors = self.determine_match_set_colors(match_sets)

        self.offset_count_intervals = IntervalTree()


        for oc in self.cumulative_counts:
            if not oc.length:
                continue
            self.offset_count_intervals[oc.offset:oc.offset + oc.length] = oc

    def get_offset_count(self, file_offset) -> sql_db.OffsetCount | None:
        if self.offset_count_intervals:
            interval: set[Interval] = self.offset_count_intervals.at(file_offset)
            if interval:
                return sorted(interval)[0].data

    def draw_file_sets(self, graph: sg.Graph, file_to_canvas_offset, y_offset = 0, y_height=200):
        if not self.cumulative_counts:
            return

        for oc in self.cumulative_counts:
            canvas_x1 = file_to_canvas_offset(oc.offset)
            canvas_x2 = file_to_canvas_offset(oc.offset + oc.length)

            fs = oc.get_frozen_set()

            count = oc.get_count()
            height = my_log(count, pixel_height=y_height)

            fill_color = self.match_set_colors.get(fs, 'green')

            graph.draw_rectangle((canvas_x1, height+y_offset),
                                 (canvas_x2, y_offset),
                                 fill_color=fill_color,
                                 line_width=0)

    def determine_match_set_colors(self, match_sets):
        color_families = [
            [f'{base_color}{n}' for n in range(1, 4)] for base_color in
            ['RoyalBlue', 'SkyBlue', 'LemonChiffon', 'Pink', 'tan', 'wheat',
             'orange', 'OrangeRed', 'VioletRed', 'SpringGreen', 'HotPink', 'Goldenrod']
        ]

        # match_sets = sorted(match_sets, key=lambda ms: -ms.count_of_bytes)
        current_set_index = 0
        for family in color_families:
            current_set = None
            try:
                while not current_set or current_set.color or not current_set.file_set:
                    current_set = match_sets[current_set_index]
                    current_set_index += 1
            except IndexError:
                break

            current_set.color = family[0]

            remaining_colors = family[1:]
            other_color_index = 0
            for other in match_sets:
                if other.color:
                    continue
                if current_set.similarity(other) > 0.80:
                    other.color = remaining_colors[other_color_index % len(remaining_colors)]
                    other_color_index += 1

        return {
            match_set.file_set: match_set.color for match_set in match_sets if match_set.color
        }


class FileView:
    """
    A FileView class is responsible for drawing information about a single file.  This may include:

    1. A MatchHistogram.  In the future, we may support multiple.
    2. The raw bytes of the file, as well as the zero-ized version of the file.
    3. Known ranges/intervals, as parsed an input by analysis tools.
    """

    def __init__(self, path, graph_name):
        self.path = path
        self.graph_name = graph_name

        self.elf_thunks = ELFThunks(path)

        with open(path, 'rb') as fd:
            self.contents = fd.read()

        self.zeroized_file = filehash.MemFile(path, True).data

        # self.values is updated when GUIView reads the event loop
        self.values = {self.graph_name: (0, 0)}
        self.hover_x = 0
        self.hover_y = 0
        self.hover_line = None

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
        for thunk in [self.elf_thunks.section_thunk, self.elf_thunks.segment_thunk]:
            for a_range, b_range, meta in sorted(thunk.all(), key=lambda x:x[0]):
                a_begin, a_len = a_range
                a_end = a_begin + a_len

                self.label_intervals.append((a_begin, a_len, meta['name']))

        self.histogram_y = self.canvas_coord_height - 300

    def draw_interval(self, y, file_begin, file_end, txt):
        x1 = self.file_to_canvas_offset(file_begin)
        x2 = self.file_to_canvas_offset(file_end)

        height = 20
        self.graph.draw_line((x1, y-height), (x1, y), width=3)
        self.graph.draw_line((x1, y), (x2, y), width=3)
        self.graph.draw_line((x2, y-height), (x2, y), width=3)
        self.graph.draw_text(txt, ((x1+x2)//2, y-30), font=(10,))

    def draw_intervals(self):
        level_maximums = [0]*9

        for file_begin, file_len, txt in self.label_intervals:
            file_end = file_begin + file_len

            maximums = ' '.join(f"{lm:6x}" for lm in level_maximums)
            for level, level_max in enumerate(level_maximums):
                if file_begin >= level_max:
                    level_maximums[level] = file_end
                    y = self.histogram_y - 60*level
                    self.draw_interval(y, file_begin, file_end, txt)
                    break

    def canvas_to_file_offset(self, x: int) -> int:
        file_view_width = self.file_x_end - self.file_x_start

        return ((x or 0) * file_view_width // self.canvas_coord_width) + self.file_x_start

    def file_to_canvas_offset(self, file_offset: int) -> int:
        file_view_width = self.file_x_end - self.file_x_start
        return (file_offset - self.file_x_start) * self.canvas_coord_width // file_view_width

    def get_hover_file_offset(self):
        if self.hover_x is None:
            return None
        return self.canvas_to_file_offset(self.hover_x)

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
            self.match_histogram.draw_file_sets(self.graph, self.file_to_canvas_offset, y_offset, 200)
        self.draw_intervals()

    def adjust_sizes(self, width, height):
        self.graph.set_size((width, height))
        self.redraw_graph()

    def set_counts(self,
                   fid_name,
                   cumulative_counts: list[sql_db.OffsetCount],
                   match_sets):

        self.match_histogram = MatchHistogram(fid_name, cumulative_counts, match_sets)

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

        # print(f'X range {self.file_x_start}  {self.file_x_end}')
        overshoot = len(self.contents) // 20

        if self.file_x_start < -overshoot:
            self.file_x_start = -overshoot
        if self.file_x_end > len(self.contents) + overshoot:
            self.file_x_end = len(self.contents) + overshoot

        self.redraw_graph()

    def update_hover(self):
        self.hover_x, self.hover_y = self.values[self.graph_name]

    def action_click(self):
        x, y = self.values[self.graph_name]
        self.drag_start_x = x
        self.drag_start_x_file = self.canvas_to_file_offset(self.drag_start_x)

    def action_drag(self):
        x, y = self.values[self.graph_name]
        file_x = self.canvas_to_file_offset(x)
        delta_x = self.drag_start_x_file - file_x

        self.hover_x = x
        self.file_x_start += delta_x
        self.file_x_end += delta_x

        self.redraw_graph()

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

    def __init__(self, file_path):
        self.view1 = FileView(file_path, 'view1')

        self.bottom_text = sg.MLine("Bottom text",
                                    size=(100, 20),
                                    font=('Fira Code', 12),
                                    background_color='grey',
                                    text_color='white',
                                    no_scrollbar=True,
                                    key='-BYTES-')

        self.bottom_text2 = sg.MLine("Bottom text",
                                     size=(100, 20),
                                     font=('Fira Code', 12),
                                     background_color='grey',
                                     text_color='white',
                                     no_scrollbar=True,
                                     key='-BYTES-')

        layout = [
            [self.view1.graph],
            [self.bottom_text, self.bottom_text2]
        ]

        screen_width, screen_height = sg.Window.get_screen_size()
        self.window = sg.Window(f'Sector Hash {file_path}',
                                layout,
                                location=(screen_width * 1 // 10, screen_height * 1 // 10),
                                finalize=True,
                                resizable=True,
                                background_color='light grey')
        self.window.refresh()

    def set_counts(self,
                   fid_name,
                   cumulative_counts: list[sql_db.OffsetCount],
                   match_sets):
        self.view1.set_counts(fid_name, cumulative_counts, match_sets)

    def adjust_sizes(self):
        window_inner_width = self.window.size[0] - 30
        self.view1.adjust_sizes(window_inner_width, 300)

        txt_width = window_inner_width // 10 // 2

        self.bottom_text.set_size((txt_width, 30))
        self.bottom_text2.set_size((txt_width, 30))

    def add_matches(self, txt: sg.MLine, view: FileView, file_offset):
        file_offset = view.get_hover_file_offset()
        oc = view.match_histogram.get_offset_count(file_offset) if view.match_histogram else None

        if oc:
            txt.print(f'Matches {oc.fileCount} files by count')
            txt.print(f'Matches {oc.hashCount} hashes by count')

            fs = oc.get_frozen_set()
            if fs:
                txt.print(f'Matches {len(fs)} files', font=('Fira Code', 12, 'bold'))
                fnames = [view.match_histogram.fid_to_name.get(fid, str(fid)) for fid in fs]
                txt.print(' '.join(sorted(fnames)[:100]))

    def update_text(self, txt: sg.MLine, view: FileView, file_offset: int):
        if file_offset is None:
            return

        # txt.update('')
        txt.print(f'File Offset {file_offset:x}  {file_offset // 1024}KB', font=('Fira Code', 12, 'bold'))

        printable_chars = bytes(string.printable.rstrip('\t\n\r\x0b\x0c'), 'ascii')

        if file_offset >= 0:
            file_bytes = view.contents[file_offset:file_offset + 128]
            byte_columns = 32
            byte_separator = 8

            ascii_line = '  '

            lines = []

            line_data = []
            line_offset = 0

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
                font_name = 'Fira Code'

                for file_byte, zero_byte in line_data:
                    if file_byte == zero_byte:
                        txt.print(file_byte.hex(), end='', text_color='black', font=(font_name, 12))
                    else:
                        txt.print(file_byte.hex(), end='', text_color='grey24', font=(font_name, 12, 'underline'))

                txt.print('  ', end='')
                for file_byte, zero_byte in line_data:
                    ascii = file_byte.decode('ascii') if file_byte in printable_chars else '.'
                    if file_byte == zero_byte:
                        txt.print(ascii, end='', font=(font_name, 12))
                    else:
                        txt.print(ascii, end='', text_color='grey30', font=(font_name, 12, 'underline'))

                txt.print('')


                # ascii_line = ''.join([fb.decode('ascii') if fb in printable_chars else '.' for fb, zb in line_data])

                # txt.print(ascii_line, end='\n')




        self.add_matches(txt, view, file_offset)


    def add_thunk_txt(self, txt: sg.MLine, view: FileView, file_offset: int):
        if view.elf_thunks:
            for thunk in view.elf_thunks.find_thunks(file_offset, only_nearest=False):
                name, translated, thunk_off, meta = thunk
                name_off = f'{name}+0x{thunk_off:x}'
                txt.print(f'Thunk {name_off:16} {translated:6x}')
                if 'struct' in meta:
                    for k, v in meta['struct'].items():
                        if isinstance(v, int):
                            v = f'0x{v:x}'
                        txt.print(f'  {k:12} = {v}')

    def update_texts(self):
        self.bottom_text.update('')
        self.bottom_text2.update('')

        file_offset = self.view1.get_hover_file_offset()
        self.update_text(self.bottom_text, self.view1, file_offset)
        self.add_thunk_txt(self.bottom_text2, self.view1, file_offset)

    def event_loop(self):
        self.adjust_sizes()

        self.window.bind("<Configure>", "+RESIZE+")

        event_actions = {}
        for event_obj, event_name, event_fx in self.view1.get_events():
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
                # print(f'Event={event}, values = {values}')

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

