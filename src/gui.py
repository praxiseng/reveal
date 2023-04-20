import itertools
import math
import sys
import filehash

import PySimpleGUI as sg
import sql_db

from intervaltree import Interval, IntervalTree


def my_log(x: int, max_value=1000, pixel_height=200) -> int:
    return int(math.log(x+1)/math.log(max_value)*pixel_height)

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

        self.assign_match_set_colors(match_sets)

        #self.draw_file_sets()

        self.offset_count_intervals = IntervalTree()
        for oc in self.cumulative_counts:
            if not oc.length:
                continue
            self.offset_count_intervals[oc.offset:oc.offset+oc.length] = oc

    def get_offset_count(self, file_offset) -> sql_db.OffsetCount | None:
        if self.offset_count_intervals:
            interval: set[Interval] = self.offset_count_intervals.at(file_offset)
            if interval:
                return sorted(interval)[0].data

    def draw_file_sets(self, graph: sg.Graph, file_to_canvas_offset):
        if not self.cumulative_counts:
            return

        for oc in self.cumulative_counts:
            canvas_x1 = file_to_canvas_offset(oc.offset)
            canvas_x2 = file_to_canvas_offset(oc.offset+oc.length)

            fs = oc.get_frozen_set()

            count = oc.get_count()
            height = my_log(count)

            fill_color = self.match_set_colors.get(fs, 'green')

            graph.draw_rectangle((canvas_x1, height), (canvas_x2, 0),
                                      fill_color=self.match_set_colors.get(fs, 'green'),
                                      line_width=0)

    def assign_match_set_colors(self, match_sets):
        color_families = [
            [f'{base_color}{n}' for n in range(1,4)] for base_color in
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
            except IndexError as e:
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

        self.match_set_colors = {
            match_set.file_set : match_set.color for match_set in match_sets if match_set.color
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

        initial_canvas_size = (width * 80 // 100, 300)
        self.graph = sg.Graph(initial_canvas_size, (0,0), (self.canvas_coord_width, 300), background_color='grey', key=graph_name)

        self.file_x_start = 0
        self.file_x_end = len(self.contents)

        self.drag_start_x = None
        self.drag_start_x_file = None

        self.match_histogram: MatchHistogram | None = None

        '''
        # Stores the sql_db.OffsetCount data for each file offset
        self.offset_count_intervals: IntervalTree | None = None
        self.cumulative_counts: list[sql_db.OffsetCount] | None = None
        self.fid_to_name: dict[int, str] | None = None
        self.match_set_colors: dict[frozenset[int], str] = {}
        '''


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

        self.hover_line = self.graph.draw_line((x, 0), (x, 300), color='white')

    def redraw_graph(self):
        self.graph.erase()
        self.update_hover_line()
        if self.match_histogram:
            self.match_histogram.draw_file_sets(self.graph, self.file_to_canvas_offset)

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
            (self.graph, '<Motion>',     self.update_hover),
            (self.graph, '<MouseWheel>', self.handle_mouse_wheel),
            (self.graph, '<Button-1>',   self.action_click),
            (self.graph, '<B1-Motion>',  self.action_drag),
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
        layout = [
            [self.view1.graph],
            [self.bottom_text]
        ]

        screenWidth, screenHeight = sg.Window.get_screen_size()
        self.window = sg.Window(f'Sector Hash {file_path}',
                                layout,
                                location=(screenWidth*1//10, screenHeight*1//10),
                                finalize=True,
                                resizable=True,
                                background_color='light grey')
        self.window.refresh()


    def set_counts(self,
                   fid_name,
                   cumulative_counts: dict[int, sql_db.OffsetCount],
                   match_sets):
        self.view1.set_counts(fid_name, cumulative_counts, match_sets)

    def adjust_sizes(self):
        window_inner_width = self.window.size[0] - 30
        self.view1.adjust_sizes(window_inner_width, 300)

        self.bottom_text.set_size((window_inner_width//10, 30))


    def update_text(self, txt: sg.MLine, view: FileView):
        file_offset = view.get_hover_file_offset()
        if file_offset is None:
            return

        txt.update('')
        txt.print(f'File Offset {file_offset:x}  {file_offset//1024}KB', font=('Fira Code', 12, 'bold'))

        if file_offset >= 0:
            file_bytes = view.contents[file_offset:file_offset + 128]
            byte_columns = 32
            byte_separator = 8
            for offset in range(0, len(file_bytes)):
                full_offset = file_offset+offset
                if offset % byte_columns == 0:
                    if offset:
                        txt.print('')
                    txt.print(f'{full_offset:6x}: ', end='')
                if full_offset % byte_separator == 0:
                    txt.print(' ', end='')

                hex_bytes = view.contents[full_offset:full_offset+1].hex()
                z_bytes = view.zeroized_file[full_offset:full_offset+1].hex()
                if hex_bytes == z_bytes:
                    txt.print(hex_bytes, end='', text_color='black', font = ('Fira Code', 12))
                else:
                    txt.print(hex_bytes, end='', text_color='grey24', font = ('Fira Code', 12, 'underline'))

            txt.print('')

        oc = view.match_histogram.get_offset_count(file_offset) if view.match_histogram else None

        if oc:
            txt.print(f'Matches {oc.fileCount} files by count')
            txt.print(f'Matches {oc.hashCount} hashes by count')

            fs = oc.get_frozen_set()
            if fs:
                txt.print(f'Matches {len(fs)} files', font=('Fira Code', 12, 'bold'))
                fnames = [view.match_histogram.fid_to_name.get(fid, str(fid)) for fid in fs]
                txt.print(' '.join(sorted(fnames)[:100]))


    def event_loop(self):
        self.adjust_sizes()

        self.window.bind("<Configure>", "+RESIZE+")

        event_actions = {}
        for event_obj, event_name, event_fx in self.view1.get_events():
            event_name2 = event_name.replace('<', '+').replace('>', '+')

            event_obj.bind(event_name, event_name2)
            event_actions[event_obj.key + event_name2] = event_fx

        while True:
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

            self.update_text(self.bottom_text, self.view1)
            self.view1.update_hover_line()

        self.window.close()


if __name__ == "__main__":
    file = FileView(sys.argv[1], 'the_graph')
    file.event_loop()