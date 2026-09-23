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
        self.rate_state = None

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
        self.parser.add_argument("--rate-ttl", dest="rate_ttl", type=float,
                                 default=DEFAULT_RATE_TTL,
                                 help="Drop counters not seen for this many "
                                      "seconds from the rate state file "
                                      "(default: %(default)s)")
        self.parser.add_argument("--rate-id", dest="rate_id", default=None,
                                 help="Stable identity of this check for the "
                                      "rate state file (default: derived "
                                      "from argv)")

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

    def get_rate_state(self):
        if self.rate_state is None:
            self.rate_state = RateState(
                rate_state_path(getattr(self.args, "rate_id", None)),
                ttl=getattr(self.args, "rate_ttl", DEFAULT_RATE_TTL))
        return self.rate_state

    def get_rate(self, label, value):
        wanted = set(self.args.rates or []) | set(self.filtered_rates or [])
        if label not in wanted:
            return False
        return self.get_rate_state().rate(label, value)

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
        if self.rate_state is not None:
            self.rate_state.save()
            for error in self.rate_state.errors:
                self.unknown_on.append(error)
                self.exitcode = 3
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


DEFAULT_RATE_TTL = 3600


def rate_state_path(rate_id=None):
    """Sciezka pliku stanu. Nazwa celowo identyczna jak wczesniej, zeby
    istniejace pliki przezyly upgrade - rate_id tylko jesli podany jawnie."""
    user = getpass.getuser()
    if rate_id is None:
        script_name = os.path.basename(__file__)
        script_args = "-".join(sys.argv)
        rate_id = script_name + script_args
    hashname = hashlib.md5((user + rate_id).encode('utf-8')).hexdigest()
    if user == "root":
        rate_dir = "/var/run"
    else:
        rate_dir = "/tmp"
    return "{}/nagios-{}".format(rate_dir, hashname)


class RateState(object):
    """Stan licznikow dla rate'ow: jeden odczyt i jeden zapis na przebieg,
    z wygasaniem wpisow, ktorych juz nie widzimy (efemeryczne veth)."""

    def __init__(self, path, ttl=DEFAULT_RATE_TTL):
        self.path = path
        self.ttl = ttl
        self.previous = {}
        self.current = {}
        self.errors = []
        self._loaded = False

    def load(self):
        if self._loaded:
            return
        self._loaded = True
        try:
            with open(self.path) as statefile:
                data = json.load(statefile)
        except (IOError, OSError):
            data = {}
        except ValueError as exc:
            self.errors.append(
                "rate file {} unreadable ({}), reseeding".format(
                    self.path, exc))
            data = {}
        self.previous = data if isinstance(data, dict) else {}

    def rate(self, label, value, now=None):
        """Zwraca (nazwa, rate) albo False - jak stare calculate_rate()."""
        self.load()
        if now is None:
            now = time.time()
        self.current[label] = (value, now)
        previous = self.previous.get(label)
        if not previous:
            return False
        try:
            previous_value = float(previous[0])
            previous_time = float(previous[1])
        except (TypeError, ValueError, IndexError, KeyError):
            return False
        time_delta = now - previous_time
        if time_delta <= 0:
            return False
        delta = value - previous_value
        if delta < 0:
            # licznik wyzerowany albo interfejs odtworzony pod ta sama nazwa
            return False
        return (label + "_rate", delta / time_delta)

    def save(self):
        """Zapis atomowy. Wpisy niewidziane w tym przebiegu wygasaja po ttl."""
        self.load()
        cutoff = time.time() - self.ttl
        merged = {}
        for label, entry in self.previous.items():
            try:
                if float(entry[1]) >= cutoff:
                    merged[label] = entry
            except (TypeError, ValueError, IndexError, KeyError):
                continue
        merged.update(self.current)
        tmpname = "{}.{}.tmp".format(self.path, os.getpid())
        try:
            with open(tmpname, "w") as statefile:
                json.dump(merged, statefile, separators=(",", ":"))
                statefile.flush()
                os.fsync(statefile.fileno())
            os.rename(tmpname, self.path)
        except (IOError, OSError) as exc:
            try:
                os.unlink(tmpname)
            except OSError:
                pass
            self.errors.append(
                "cannot write rate file {}: {}".format(self.path, exc))


def calculate_rate(label, value):
    """Zgodnosc wsteczna: pojedynczy odczyt/zapis. Wewnatrz PynagioCheck
    uzywany jest RateState, ktory robi jedno IO na caly przebieg."""
    state = RateState(rate_state_path())
    result = state.rate(label, value)
    state.save()
    return result


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
