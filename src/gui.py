import itertools
import math
import sys
import filehash

import PySimpleGUI as sg
import sql_db

from intervaltree import Interval, IntervalTree


def my_log(x: int, max_value = 1000, pixel_height=200) -> int:
    #if x == 0:
    #    return x
    #result = 0

    return int(math.log(x+1)/math.log(max_value)*pixel_height)

class FileView:

    def __init__(self, path):
        self.path = path
        with open(path, 'rb') as fd:
            self.contents = fd.read()

        self.zeroized_file = filehash.MemFile(path, True).data

        self.hover_x = 0
        self.hover_y = 0
        self.hover_line = None

        #self.file_set_at_offset = None


        self.cumulative_counts = None
        self.fid_to_name = None

        self.init_graph()

        self.offset_count_intervals: IntervalTree | None = None

        self.file_x_start = 0
        self.file_x_end = len(self.contents)

    def init_graph(self):
        self.canvas_width = 1000
        self.canvas_coord_width = 10000

        canvas_size = (self.canvas_width, 300)
        graph_obj = sg.Graph(canvas_size, (0,0), (self.canvas_coord_width, 300), background_color='grey', key='graph')
        layout = [
            [graph_obj],
            [sg.MLine("Bottom text",
                      size=(100, 20),
                      font=('Fira Code', 12),
                      background_color='grey',
                      text_color='white',
                      no_scrollbar=True,
                      key='-BYTES-')]
        ]

        self.window = sg.Window(f'Sector Hash {self.path}', layout, finalize=True, resizable=True, background_color='light grey')
        self.window.refresh()
        self.graph = self.window['graph']
        self.text_data_display = self.window['-BYTES-']


    def canvas_to_file_offset(self, x: int) -> int:
        file_view_width = self.file_x_end - self.file_x_start

        return ((x or 0) * file_view_width // self.canvas_coord_width) + self.file_x_start

    def file_to_canvas_offset(self, file_offset: int) -> int:
        file_view_width = self.file_x_end - self.file_x_start
        return (file_offset - self.file_x_start) * self.canvas_coord_width // file_view_width

    def update_text(self):
        if self.hover_x is None:
            return

        file_offset = self.canvas_to_file_offset(self.hover_x)

        txt = self.window['-BYTES-']

        txt.update('')
        txt.print(f'File Offset {file_offset:x}  {file_offset//1024}KB', font=('Fira Code', 12, 'bold'))
        txt.print(f'Canvas Offset {self.hover_x}')

        if file_offset >= 0:
            file_bytes = self.contents[file_offset:file_offset + 128]
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

                hex_bytes = self.contents[full_offset:full_offset+1].hex()
                z_bytes = self.zeroized_file[full_offset:full_offset+1].hex()
                if hex_bytes == z_bytes:
                    txt.print(hex_bytes, end='', text_color='black', font = ('Fira Code', 12))
                else:
                    txt.print(hex_bytes, end='', text_color='grey24', font = ('Fira Code', 12, 'underline'))

            txt.print('')


        oc: sql_db.OffsetCount | None = None
        if self.offset_count_intervals:
            interval: set[Interval] = self.offset_count_intervals.at(file_offset)
            if interval:
                oc = sorted(interval)[0].data

        if oc:
            txt.print(f'Matches {oc.fileCount} files by count')
            txt.print(f'Matches {oc.hashCount} hashes by count')

            fs = oc.get_frozen_set()
            if fs:
                txt.print(f'Matches {len(fs)} files', font=('Fira Code', 12, 'bold'))
                fnames = [self.fid_to_name.get(fid, str(fid)) for fid in fs]
                txt.print(' '.join(sorted(fnames)[:100]))


    def update_hover_line(self):
        if self.hover_line is not None:
            self.graph.delete_figure(self.hover_line)

        # Do the conversion to snap to an offset
        x = self.file_to_canvas_offset(self.canvas_to_file_offset(self.hover_x))

        self.hover_line = self.graph.draw_line((x, 0), (x, 300), color='white')

    def redraw_graph(self):
        self.graph.erase()
        self.update_hover_line()
        self.draw_file_sets()

    def adjust_sizes(self):
        print(f'Window size {self.window.size}')

        self.canvas_width = self.window.size[0]-30
        self.graph.set_size((self.canvas_width, 300))
        self.text_data_display.set_size((self.canvas_width//10, 30))

        self.redraw_graph()

    def draw_file_sets(self):
        if not self.cumulative_counts:
            return

        for oc in self.cumulative_counts:
            oc: sql_db.OffsetCount

            canvas_x1 = self.file_to_canvas_offset(oc.offset)
            canvas_x2 = self.file_to_canvas_offset(oc.offset+oc.length)

            fs = oc.get_frozen_set()

            count = oc.get_count()
            height = my_log(count)

            fill_color = self.match_set_colors.get(fs, 'green')

            self.graph.draw_rectangle((canvas_x1, height), (canvas_x2, 0),
                                      fill_color=self.match_set_colors.get(fs, 'green'),
                                      line_width=0)


    def make_interval(self, offset_obj):
        it = IntervalTree()
        for current, next_obj in itertools.pairwise(offset_obj):
            file_offset, current_obj = current
            next_offset, next_obj = next_obj

            it[file_offset:next_offset] = current_obj
        return it

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

    def set_counts(self,
                   fid_name,
                   cumulative_counts: dict[int, sql_db.OffsetCount],
                   match_sets):

        self.cumulative_counts = cumulative_counts
        self.fid_to_name = fid_name

        self.assign_match_set_colors(match_sets)

        self.draw_file_sets()

        self.offset_count_intervals = IntervalTree()
        for oc in self.cumulative_counts:
            if not oc.length:
                continue
            self.offset_count_intervals[oc.offset:oc.offset+oc.length] = oc


    def event_loop(self):
        self.adjust_sizes()

        self.window.bind("<Configure>", "+RESIZE+")
        self.graph.bind('<Motion>', '+MOTION+')
        self.graph.bind('<MouseWheel>', '+MOUSEWHEEL+')

        while True:
            event, values = self.window.read()
            if event in ('Quit', None):  # always give ths user a way out
                break

            #print(f'Event={event}, values = {values}')
            if 'RESIZE' in event:
                self.adjust_sizes()
            if 'MOUSEWHEEL' in event:
                # print(f"Mouse {self.graph.user_bind_event.delta}")
                mouse_steps = int(self.graph.user_bind_event.delta/120)
                file_range = self.file_x_end - self.file_x_start
                if mouse_steps < 0:
                    # Zoom out
                    self.file_x_start -= file_range // 5
                    self.file_x_end += file_range // 5

                else:
                    # Zoom in
                    file_hover_x = self.canvas_to_file_offset(self.hover_x)
                    left = file_hover_x - self.file_x_start
                    right = self.file_x_end - file_hover_x
                    self.file_x_start += left // 5
                    self.file_x_end -= right // 5

                # print(f'X range {self.file_x_start}  {self.file_x_end}')
                overshoot = len(self.contents) // 10

                if self.file_x_start < -overshoot:
                    self.file_x_start = -overshoot
                if self.file_x_end > len(self.contents) + overshoot:
                    self.file_x_end = len(self.contents) + overshoot

                self.redraw_graph()


            self.hover_x, self.hover_y = values['graph']

            self.update_text()
            self.update_hover_line()


        self.window.close()


if __name__ == "__main__":
    file = FileView(sys.argv[1])
    file.event_loop()