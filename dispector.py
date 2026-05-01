import json
import queue
import sys
import traceback
from datetime import datetime
from typing import Any, Dict, List

from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QSplitter,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from dis_receiver import DisReceiver, PacketRecord


MAX_PACKETS = 5000


class DispectorWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("DISpector")
        self.resize(1500, 900)

        self._all_packets: List[PacketRecord] = []
        self._visible_packets: List[PacketRecord] = []
        self._pending_packets: "queue.SimpleQueue[PacketRecord]" = queue.SimpleQueue()
        self._pending_errors: "queue.SimpleQueue[str]" = queue.SimpleQueue()

        self.receiver = DisReceiver(self._enqueue_packet, self._enqueue_error)

        self._build_ui()

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self._drain_queues)
        self.refresh_timer.start(150)

    def _build_ui(self) -> None:
        central = QWidget(self)
        root = QVBoxLayout(central)
        self.setCentralWidget(central)

        root.addWidget(self._build_connection_group())
        root.addWidget(self._build_filter_group())

        splitter = QSplitter(Qt.Vertical, self)
        splitter.addWidget(self._build_packet_table())
        splitter.addWidget(self._build_details_panel())
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)

        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)
        self._set_status("Idle")

    def _build_connection_group(self) -> QGroupBox:
        group = QGroupBox("Network")
        layout = QHBoxLayout(group)

        form = QFormLayout()
        self.bind_host_edit = QLineEdit("0.0.0.0")
        self.bind_port_edit = QLineEdit("3000")

        form.addRow("Listen Host", self.bind_host_edit)
        form.addRow("Listen Port", self.bind_port_edit)
        layout.addLayout(form)

        button_column = QVBoxLayout()
        self.start_button = QPushButton("Start Capture")
        self.stop_button = QPushButton("Stop Capture")
        self.clear_button = QPushButton("Clear Packets")
        self.stop_button.setEnabled(False)

        self.start_button.clicked.connect(self._start_capture)
        self.stop_button.clicked.connect(self._stop_capture)
        self.clear_button.clicked.connect(self._clear_packets)

        button_column.addWidget(self.start_button)
        button_column.addWidget(self.stop_button)
        button_column.addWidget(self.clear_button)
        button_column.addStretch(1)
        layout.addLayout(button_column)

        return group

    def _build_filter_group(self) -> QGroupBox:
        group = QGroupBox("Filters")
        layout = QHBoxLayout(group)

        self.pdu_type_combo = QComboBox()
        self.pdu_type_combo.addItem("All")
        self.pdu_type_combo.setMinimumContentsLength(20)
        self.pdu_type_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.entity_name_edit = QLineEdit()
        self.entity_name_edit.setPlaceholderText("substring match")
        self.application_id_edit = QLineEdit()
        self.application_id_edit.setPlaceholderText("e.g. 1,5,42")

        self.pdu_type_combo.currentTextChanged.connect(self._apply_filters)
        self.entity_name_edit.textChanged.connect(self._apply_filters)
        self.application_id_edit.textChanged.connect(self._apply_filters)

        layout.addWidget(QLabel("PDU Type"))
        layout.addWidget(self.pdu_type_combo)
        layout.addWidget(QLabel("Entity Name"))
        layout.addWidget(self.entity_name_edit)
        layout.addWidget(QLabel("Application IDs"))
        layout.addWidget(self.application_id_edit)

        return group

    def _build_packet_table(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)

        self.packet_table = QTableWidget(0, 9, self)
        self.packet_table.setHorizontalHeaderLabels(
            [
                "#",
                "Time",
                "PDU Type",
                "Entity Name",
                "App ID",
                "Site",
                "Entity",
                "Bytes",
                "Source",
            ]
        )
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.itemSelectionChanged.connect(self._show_selected_packet)

        layout.addWidget(self.packet_table)
        return panel

    def _build_details_panel(self) -> QWidget:
        panel = QWidget()
        layout = QHBoxLayout(panel)

        self.details_tree = QTreeWidget(self)
        self.details_tree.setHeaderLabels(["Field", "Value"])
        self.details_tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.details_tree.header().setStretchLastSection(True)

        self.raw_text = QPlainTextEdit(self)
        self.raw_text.setReadOnly(True)
        self.raw_text.setFont(QFont("Consolas", 10))

        layout.addWidget(self.details_tree, 2)
        layout.addWidget(self.raw_text, 3)
        return panel

    def _start_capture(self) -> None:
        try:
            bind_host = self.bind_host_edit.text().strip() or "0.0.0.0"
            bind_port = int(self.bind_port_edit.text().strip())

            self.receiver.start(
                bind_host=bind_host,
                bind_port=bind_port,
            )
        except Exception as exc:
            QMessageBox.critical(self, "Capture Error", str(exc))
            return

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self._set_status(f"Capturing on {bind_host}:{bind_port}")

    def _stop_capture(self) -> None:
        self.receiver.stop()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self._set_status("Capture stopped")

    def _clear_packets(self) -> None:
        self._all_packets.clear()
        self._visible_packets.clear()
        self.packet_table.setRowCount(0)
        self.details_tree.clear()
        self.raw_text.clear()
        self._rebuild_pdu_type_filter()
        self._set_status("Packets cleared")

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self.receiver.stop()
        super().closeEvent(event)

    def _enqueue_packet(self, packet: PacketRecord) -> None:
        self._pending_packets.put(packet)

    def _enqueue_error(self, error_message: str) -> None:
        self._pending_errors.put(error_message)

    def _drain_queues(self) -> None:
        latest_error = None
        while True:
            try:
                latest_error = self._pending_errors.get_nowait()
            except queue.Empty:
                break
        if latest_error:
            self._set_status(latest_error)

        new_packets: List[PacketRecord] = []
        while True:
            try:
                new_packets.append(self._pending_packets.get_nowait())
            except queue.Empty:
                break
        if not new_packets:
            return

        self._all_packets.extend(new_packets)

        if len(self._all_packets) > MAX_PACKETS:
            overflow = len(self._all_packets) - MAX_PACKETS
            self._all_packets = self._all_packets[overflow:]

        self._rebuild_pdu_type_filter()
        self._apply_filters()
        self._set_status(f"Captured {len(self._all_packets)} packet(s)")

    def _rebuild_pdu_type_filter(self) -> None:
        current = self.pdu_type_combo.currentText()
        known_types = sorted({packet.pdu_type for packet in self._all_packets})

        self.pdu_type_combo.blockSignals(True)
        self.pdu_type_combo.clear()
        self.pdu_type_combo.addItem("All")
        self.pdu_type_combo.addItems(known_types)
        index = self.pdu_type_combo.findText(current)
        self.pdu_type_combo.setCurrentIndex(index if index >= 0 else 0)
        self.pdu_type_combo.blockSignals(False)

    def _parse_application_filter(self) -> List[int]:
        raw = self.application_id_edit.text().strip()
        if not raw:
            return []

        values: List[int] = []
        for chunk in raw.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            try:
                values.append(int(chunk))
            except ValueError:
                continue
        return values

    def _apply_filters(self) -> None:
        selected_pdu_type = self.pdu_type_combo.currentText()
        name_filter = self.entity_name_edit.text().strip().lower()
        application_ids = self._parse_application_filter()

        visible_packets: List[PacketRecord] = []
        for packet in self._all_packets:
            if selected_pdu_type != "All" and packet.pdu_type != selected_pdu_type:
                continue
            if name_filter and name_filter not in packet.entity_name.lower():
                continue
            if application_ids and packet.application_id not in application_ids:
                continue
            visible_packets.append(packet)

        self._visible_packets = visible_packets
        self._render_packet_table()

    def _render_packet_table(self) -> None:
        selected_sequence = None
        selected_items = self.packet_table.selectedItems()
        if selected_items:
            selected_sequence = selected_items[0].data(Qt.UserRole)

        self.packet_table.setRowCount(len(self._visible_packets))
        for row, packet in enumerate(self._visible_packets):
            values = [
                str(packet.sequence),
                datetime.fromtimestamp(packet.received_at).strftime("%H:%M:%S.%f")[:-3],
                packet.pdu_type,
                packet.entity_name,
                "" if packet.application_id is None else str(packet.application_id),
                "" if packet.site_id is None else str(packet.site_id),
                "" if packet.entity_id is None else str(packet.entity_id),
                str(packet.size_bytes),
                f"{packet.source_host}:{packet.source_port}",
            ]

            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.UserRole, packet.sequence)
                self.packet_table.setItem(row, column, item)

        if self._visible_packets:
            for row, packet in enumerate(self._visible_packets):
                if packet.sequence == selected_sequence:
                    self.packet_table.selectRow(row)
                    break
            else:
                self.packet_table.selectRow(0)
        else:
            self.details_tree.clear()
            self.raw_text.clear()

    def _show_selected_packet(self) -> None:
        row = self.packet_table.currentRow()
        if row < 0 or row >= len(self._visible_packets):
            return

        packet = self._visible_packets[row]
        self.details_tree.clear()
        root = QTreeWidgetItem(["PDU", packet.pdu_type])
        self.details_tree.addTopLevelItem(root)

        metadata = QTreeWidgetItem(["Metadata", ""])
        root.addChild(metadata)
        for field_name, field_value in [
            ("sequence", packet.sequence),
            ("received_at", datetime.fromtimestamp(packet.received_at).isoformat(timespec="milliseconds")),
            ("source", f"{packet.source_host}:{packet.source_port}"),
            ("bytes", packet.size_bytes),
            ("summary", packet.summary),
        ]:
            metadata.addChild(QTreeWidgetItem([field_name, str(field_value)]))

        payload = QTreeWidgetItem(["Payload", ""])
        root.addChild(payload)
        self._append_tree_items(payload, packet.details)
        self.details_tree.expandToDepth(2)

        self.raw_text.setPlainText(
            json.dumps(packet.details, indent=2, sort_keys=True, default=str)
            + "\n\nRaw Bytes (hex)\n"
            + packet.raw_hex
            + "\n\nASCII Interpretation\n"
            + packet.raw_ascii
        )

    def _append_tree_items(self, parent: QTreeWidgetItem, value: Any, key_name: str = "") -> None:
        if isinstance(value, dict):
            items = sorted(value.items(), key=lambda item: str(item[0]))
            for key, nested_value in items:
                branch = QTreeWidgetItem([str(key), "" if isinstance(nested_value, (dict, list)) else str(nested_value)])
                parent.addChild(branch)
                if isinstance(nested_value, (dict, list)):
                    self._append_tree_items(branch, nested_value, str(key))
            return

        if isinstance(value, list):
            for index, item in enumerate(value):
                display_value = "" if isinstance(item, (dict, list)) else self._format_tree_value(item, key_name)
                branch = QTreeWidgetItem([f"[{index}]", display_value])
                parent.addChild(branch)
                if isinstance(item, (dict, list)):
                    self._append_tree_items(branch, item, f"{key_name}[{index}]")
            return

        parent.addChild(QTreeWidgetItem([key_name or "value", self._format_tree_value(value, key_name)]))

    def _format_tree_value(self, value: Any, key_name: str) -> str:
        if key_name == "characters" and isinstance(value, int):
            if value == 0:
                return "0 ('\\0')"
            if 32 <= value <= 126:
                return f"{value} ('{chr(value)}')"
            return f"{value} ('\\x{value:02x}')"
        return str(value)

    def _set_status(self, message: str) -> None:
        self.status_bar.showMessage(message)


def main() -> int:
    app = QApplication(sys.argv)
    window = DispectorWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        traceback.print_exc()
        raise
