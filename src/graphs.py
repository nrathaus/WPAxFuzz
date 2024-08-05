import subprocess


class graphss:
    def __init__(self, path):
        self.txt_path = path
        self.bursty_24g = ""
        self.nobursty_24g = ""
        self.bursty_5g = ""
        self.nobursty_5g = ""
        self.get_Instances()
        self.string_to_search = []
        self.addString()

    def get_Instances(self):
        try:
            self.bursty_24g = subprocess.check_output(
                ["cat " + self.txt_path + " | grep BURSTY | grep -v 5G"], shell=True
            )
        except Exception:
            self.bursty_24g = ""

        try:
            self.nobursty_24g = subprocess.check_output(
                [
                    "cat "
                    + self.txt_path
                    + " | grep -v BURSTY | grep -v 5G | grep -v DISCONNECTED"
                ],
                shell=True,
            )
        except Exception:
            self.noBursty_24 = ""

        try:
            self.bursty_5g = subprocess.check_output(
                ["cat " + self.txt_path + " | grep BURSTY | grep 5G "],
                shell=True,
                stderr=subprocess.STDOUT,
            )
        except Exception:
            self.bursty_5g = ""

        try:
            self.nobursty_5g = subprocess.check_output(
                [
                    "cat "
                    + self.txt_path
                    + " | grep -v BURSTY | grep 5G | grep -v DISCONNECTED"
                ],
                shell=True,
            )
        except Exception:
            self.nobursty_5g = ""

    def average_per_Attackstr(self, name, string_of_Output):
        diferrent_Values = []

        if len(string_of_Output) > 3:
            alllines = string_of_Output.split("\n")

            print("\n\n" + "-" * 40 + name + "-" * 40)
            for strings in self.string_to_search:
                counter = 0
                average = 0
                for lines in alllines:
                    if strings in lines:
                        a = lines.split()[5]
                        a = float("{:.2f}".format(float(a)))
                        counter = counter + 1
                        average = average + a

                if counter > 0 and average > 0:
                    average = float("{:.2f}".format(float(average / counter)))
                    diferrent_Values.append(average)
                    print(
                        "["
                        + strings
                        + "]:  Average not-responding time: "
                        + str(average)
                        + "s || Instances:  "
                        + str(counter)
                    )

                # [int(s) for s in lines.split() if s.isdigit()]

    def average_per_Value(self, name, string_of_Output, listofLists):
        if len(string_of_Output) > 3:
            alllines = string_of_Output.split("\n")
            print("\n\n" + "-" * 40 + name + "-" * 40)
            for list_item in listofLists:
                counter = 0
                average = 0
                auth = list_item[0]
                seq = list_item[1]
                status = list_item[2]

                for line in alllines:
                    if (" " + str(auth) + " " + str(seq) + " " + str(status)) in line:
                        a = line.split()[5]
                        a = float("{:.2f}".format(float(a)))
                        counter = counter + 1
                        average = average + a

                if counter > 0 and average > 0:
                    average = float("{:.2f}".format(float(average / counter)))

                    print(
                        "For values ["
                        + str(auth)
                        + " "
                        + str(seq)
                        + " "
                        + str(status)
                        + "]:  Average not-responding time: "
                        + str(average)
                        + "s || Instances:  "
                        + str(counter)
                    )

    def addString(self):
        self.string_to_search.append("eempty body frames with values")
        self.string_to_search.append(
            "valid commits folowed by empty body frames with values"
        )
        self.string_to_search.append(
            "valid commits folowed by confirm with send-confirm value = 0"
        )
        self.string_to_search.append(
            "valid commits folowed by confirm with send-confirm value = 2"
        )
        self.string_to_search.append("commits with body values")
        self.string_to_search.append("confirms with send-confirm value = 0")
        self.string_to_search.append("confirms with send-confirm value = 2")

    def go(self, listofValues):
        self.average_per_Attackstr("2.4g", self.nobursty_24g)
        self.average_per_Attackstr("2.4g Bursts", self.bursty_24g)
        self.average_per_Attackstr("5g ", self.nobursty_5g)
        self.average_per_Attackstr("5g Bursts", self.bursty_5g)

        self.average_per_Value("2.4g", self.nobursty_24g, listofValues)
        self.average_per_Value("2.4g Bursts", self.bursty_24g, listofValues)
        self.average_per_Value("5g ", self.nobursty_5g, listofValues)
        self.average_per_Value("5g Bursts", self.bursty_5g, listofValues)


def statisticss(path, listofLists):
    graph = graphss(path)
    graph.go(listofLists)
