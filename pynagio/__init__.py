from __future__ import print_function
import sys
import os
import re
import time
import getpass
import hashlib
import json
import pynagio.prefixes as prefixes
import pynagio.hacked_argument_parser as hacked_argument_parser


class PynagioCheck(object):

    def __init__(self):
        self.options = []
        self.metrics = {}
        self.metrics_regex = []
        self.thresholds = []
        self.checked_thresholds = []
        self.threshold_regexes = []
        self.filtered_thresholds = []
        self.summary = []
        self.output = []
        self.perfdata = []
        self.perfdata_regex = []
        self.rates = {}
        self.rate_regexes = []
        self.filtered_rates = []
        self.exitcode = 0
        self.critical_on = []
        self.warning_on = []
        self.unknown_on = []

        self.parser = hacked_argument_parser.HackedArgumentParser()
        self.parser.add_argument("-t", nargs='+', dest="thresholds",
                                 help="Threshold(s) to check")
        self.parser.add_argument("-T", nargs='+', dest="threshold_regexes",
                                 help="Threshold regex(es) to check")
        self.parser.add_argument("--no-perfdata", "--np", action='store_true',
                                 help="Do not print perfdata")
        self.parser.add_argument("--no-long-output", "--nl",
                                 action='store_true',
                                 help="Do not print long output")
        self.parser.add_argument("-r", nargs='+', dest="rates",
                                 help="Rates to calculate")
        self.parser.add_argument("-R", nargs='+', dest="rate_regexes",
                                 help="Rates regex to calculate")
        self.parser.add_argument("-B", nargs='+', dest="blacklist_regexes",
                                 help="Blacklist regexes")

    def add_option(self, *args, **kwargs):
        self.parser.add_argument(*args, **kwargs)

    def parse_arguments(self):
        self.args = self.parser.parse_args()

    def add_summary(self, summary):
        self.summary.append(summary)

    def add_output(self, output):
        self.output.append((output))

    def add_perfdata(self, label, value):
        self.perfdata.append("{}={}".format(label, value))

    def parse_thresholds(self):
        if self.args.thresholds:
            for threshold in self.args.thresholds:
                parsed_threshold = parse_threshold(threshold)
                self.thresholds.append(parsed_threshold)
                self.args.thresholds.remove(threshold)
        if self.filtered_thresholds:
            for threshold in self.filtered_thresholds:
                parsed_threshold = parse_threshold(threshold)
                self.thresholds.append(parsed_threshold)
                self.filtered_thresholds.remove(threshold)

    def check_thresholds(self, metrics):
        if self.thresholds:
            for threshold in self.thresholds:
                label = threshold['label']
                if label in metrics.keys():
                    value = float(metrics[label])
                    checked_threshold = threshold
                    checked_threshold['value'] = value
                    if 'prefix' in threshold:
                        for name in ['ok', 'crit', 'warn']:
                            if name in threshold:
                                threshold[name][0] = (
                                    threshold[name][0]
                                    * prefixes.prefixes[threshold['prefix']])
                                threshold[name][1] = (
                                    threshold[name][1]
                                    * prefixes.prefixes[threshold['prefix']])
                    if 'ok' in threshold:
                        if threshold['ok'][0] < value <= threshold['ok'][1]:
                            checked_threshold['exitcode'] = 0
                            self.checked_thresholds.append(checked_threshold)
                            continue
                    if 'crit' in threshold:
                        if ((threshold['crit'][0] < value) and
                                (value <= threshold['crit'][1])):
                            checked_threshold['exitcode'] = 2
                            self.checked_thresholds.append(checked_threshold)
                            continue
                    if 'warn' in threshold:
                        if ((threshold['warn'][0] < value) and
                                (value <= threshold['warn'][1])):
                            checked_threshold['exitcode'] = 1
                            self.checked_thresholds.append(checked_threshold)
                            continue
                    if 'ok' in threshold:
                        checked_threshold['exitcode'] = 2
                        self.checked_thresholds.append(checked_threshold)
                        continue
                    checked_threshold['exitcode'] = 0
                    self.checked_thresholds.append(checked_threshold)
                else:
                    self.unknown_on.append(
                        "No such metric {}".format(label))
                    self.exitcode = 3

    def filter_threshold_regexes(self, label):
        if self.args.threshold_regexes:
            for threshold_regex in self.args.threshold_regexes:
                parsed_threshold_regex = parse_threshold_regex(
                    threshold_regex)
                label_regex = parsed_threshold_regex['label_regex']
                rest = parsed_threshold_regex['rest']
                if label_regex.match(label):
                    self.filtered_thresholds.append(
                        "metric={},{}".format(label, rest))

    def filter_threshold_regexes_labels(self, labels):
        if self.args.threshold_regexes:
            for threshold_regex in self.args.threshold_regexes:
                parsed_threshold_regex = parse_threshold_regex(
                    threshold_regex)
                label_regex = parsed_threshold_regex['label_regex']
                rest = parsed_threshold_regex['rest']
                matched_labels = match_regex_labels(label_regex, labels)
                if matched_labels:
                    for matched_label in matched_labels:
                        self.filtered_thresholds.append(
                            "metric={},{}".format(matched_label, rest))
                else:
                    self.unknown_on.append(
                        "No match for threshold regex {}".format(
                            threshold_regex))
                    self.exitcode = 3

    def get_rate(self, label, value):
        calculated_rate = calculate_rate(label, value)
        if self.args.rates:
            if label in self.args.rates and calculated_rate:
                rate_name, rate = calculated_rate
                return rate_name, rate
        if self.filtered_rates:
            if label in self.filtered_rates and calculated_rate:
                rate_name, rate = calculated_rate
                return rate_name, rate
        return False

    def add_metrics(self, metrics):
        if not metrics:
            print("UNKNOWN: no metrics provided")
            sys.exit(3)
        if not isinstance(metrics, dict):
            print("UNKNOWN: no dict of metrics provided")
            sys.exit(3)
        if not hasattr(self, "args"):
            self.parse_arguments()
        if (hasattr(self.args, "blacklist_regexes") and
                self.args.blacklist_regexes):
            blacklisted_labels = []
            for blacklist_regex in self.args.blacklist_regexes:
                blacklisted_labels.extend(
                    match_regex_labels(blacklist_regex, metrics.keys()))
            if blacklisted_labels:
                metrics = {label: metrics[label]
                           for label in metrics
                           if label not in blacklisted_labels}
        if hasattr(self.args, "rate_regexes") and self.args.rate_regexes:
            for rate_regex in self.args.rate_regexes:
                matched_labels = match_regex_labels(rate_regex,
                                                    metrics.keys())
                if matched_labels:
                    self.filtered_rates.extend(matched_labels)
                else:
                    self.unknown_on.append(
                        "No match for rate regex {}".format(rate_regex))
                    self.exitcode = 3
        for label in metrics:
            if self.filtered_rates:
                if label in self.filtered_rates:
                    value = float(metrics[label])
                    rate_value = self.get_rate(label, value)
                    if rate_value:
                        rate_name, rate = rate_value
                        self.rates[rate_name] = rate
        if self.args.rates:
            for name in self.args.rates:
                if name not in metrics:
                    self.unknown_on.append(
                        "No such metric {}".format(name))
                    self.exitcode = 3
                else:
                    value = float(metrics[name])
                    rate_value = self.get_rate(name, value)
                    if rate_value:
                        rate_name, rate = rate_value
                        self.rates[rate_name] = rate
        if self.rates:
            metrics.update(self.rates)
        self.filter_threshold_regexes_labels(metrics.keys())
        self.metrics = metrics
        for label in metrics:
            value = float(metrics[label])
            self.add_perfdata(label, value)
            self.parse_thresholds()
        self.check_thresholds(metrics)

    def exit(self):
        if self.checked_thresholds:
            for threshold in self.checked_thresholds:
                if threshold['exitcode'] == 2:
                    self.exitcode = 2
                    break
            if self.exitcode != 2:
                for threshold in self.checked_thresholds:
                    if threshold['exitcode'] == 1:
                        self.exitcode = 1
                        break
            for threshold in self.checked_thresholds:
                if threshold['exitcode'] == 2:
                    self.critical_on.append("{} = {}".format(
                        threshold['label'], "{:.2f}".format(
                            threshold['value'])))
                if threshold['exitcode'] == 1:
                    self.warning_on.append("{} = {}".format(
                        threshold['label'], "{:.2f}".format(
                            threshold['value'])))
        summary_line = ""
        if self.summary:
            summary_line += " ".join(self.summary) + " "
        if self.critical_on:
            summary_line += "CRITICAL on " + " ".join(
                self.critical_on) + " "
        if self.warning_on:
            summary_line += "WARNING on " + " ".join(
                self.warning_on) + " "
        if self.unknown_on:
            summary_line += "UNKNOWN: " + " ".join(
                self.unknown_on) + " "
        if self.exitcode == 0:
            summary_line += "OK"
        print(summary_line,end=' '),
        if self.args.no_long_output:
            if self.output:
                print(self.output)
        else:
            for label in self.metrics:
                print("{} = {}".format(label, self.metrics[label]))
        if not self.args.no_perfdata:
            if self.perfdata:
                print(" | ", end='')
                print(" ".join(self.perfdata))
        sys.exit(self.exitcode)


def parse_threshold(threshold):
    parsed_threshold = {}
    for kval in [part.split("=") for part in threshold.split(",")]:
        if kval[0] == 'metric':
            parsed_threshold['label'] = kval[1]
        if kval[0] in ['ok', 'crit', 'warn']:
            parsed_threshold[kval[0]] = [float(x) for x
                                         in kval[1].split("..")]
        if kval[0] == 'prefix':
            parsed_threshold['prefix'] = kval[1]
    return parsed_threshold


def parse_threshold_regex(threshold_regex):
    parsed_threshold_regex = {}
    parsed_threshold_regex['rest'] = ""
    for kval in threshold_regex.split(","):
        if kval.split("=")[0] == "metric":
            parsed_threshold_regex['label_regex'] = re.compile(
                kval.split("=")[1])
        else:
            parsed_threshold_regex['rest'] += "," + kval
    return parsed_threshold_regex


def calculate_rate(label, value):
    time_now = time.time()
    value_now = {label: (value, time_now)}
    user = getpass.getuser()
    script_name = os.path.basename(__file__)
    script_args = "-".join(sys.argv)
    hashname = (hashlib.md5((user + script_name
                             + script_args).encode('utf-8')).hexdigest())
    if user == "root":
        rate_dir = "/var/run"
        rate_filename = "{}/nagios-{}".format(rate_dir, hashname)
    else:
        rate_dir = "/tmp"
        rate_filename = "{}/nagios-{}".format(rate_dir, hashname)
    if os.path.exists(rate_filename):
        try:
            with open(rate_filename, "r+") as ratefile:
                values_from_file = json.load(ratefile)
                if label in values_from_file:
                    delta = value - values_from_file[label][0]
                    time_delta = time_now - values_from_file[label][1]
                    rate = delta / time_delta
                    rate_name = label + "_rate"
                    values_from_file[label] = (value, time_now)
                    with open(rate_filename, "w+") as ratefile:
                        json.dump(values_from_file, ratefile,
                                  ensure_ascii=False, sort_keys=True,
                                  indent=4)
                    return (rate_name, rate)
                else:
                    values_from_file.update(value_now)
                    with open(rate_filename, "w+") as ratefile:
                        json.dump(values_from_file, ratefile,
                                  ensure_ascii=False, sort_keys=True,
                                  indent=4)
        except Exception as exc:
            print(str(exc))
            try:
                with open(rate_filename, "w+") as ratefile:
                    json.dump(value_now, ratefile, ensure_ascii=False,
                              sort_keys=True, indent=4)
            except IOError as ioe:
                print("Cannot write to the rate file {}".format(rate_filename))
                print(str(ioe))
                sys.exit(2)
            return False
    else:
        try:
            with open(rate_filename, "w+") as ratefile:
                time_now = time.time()
                value_now = {label: (value, time_now)}
                json.dump(value_now, ratefile, ensure_ascii=False,
                          sort_keys=True, indent=4)
        except IOError as ioe:
            print("Cannot create rate file in {}".format(rate_dir))
            print(str(ioe))
            sys.exit(2)
        return False


def match_label(regexes, label):
    for regex in regexes:
        compiled_regex = re.compile(regex)
        if compiled_regex.search(label):
            return True
    return False


def match_regex_labels(regex, labels):
    compiled_regex = re.compile(regex)
    matched_labels = []
    for label in labels:
        if compiled_regex.search(label):
            matched_labels.append(label)
    if not matched_labels:
        return []
    return matched_labels
