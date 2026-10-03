"""Chart for the report: one judge vs two judges on the new-task test.

Data: the 129 new-task cases, scored against the author's blind labels.
- One judge: the pipeline as originally run (main judge decides; the
  second judge only on low confidence).
- Two judges: the second judge (Jev) checks every verdict, measured live
  by re-judging the same 129 cases (data/holdout_planted/rejudge_with_filter.py).

Run: python docs/report_source/judge_comparison_chart.py
Writes docs/assets/judge_comparison.png
"""

from pathlib import Path

import matplotlib.pyplot as plt

OUT = Path(__file__).resolve().parents[1] / "assets" / "judge_comparison.png"
CASES = 129

ONE = {"auto": 124, "right": 104, "false_alarms": 12, "missed": 8, "human": 5}
TWO = {"auto": 104, "right": 97, "false_alarms": 2, "missed": 5, "human": 25}

BLUE, ORANGE = "#2a78d6", "#eb6834"  # validated categorical slots 1-2
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"


def pct(n, d):
    return 100 * n / d


def style(ax):
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(colors=MUTED, length=0, labelsize=8)
    ax.yaxis.grid(True, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)


def label(ax, bars, fmt="{:.0f}%"):
    for bar in bars:
        h = bar.get_height()
        ax.annotate(fmt.format(h), (bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 2), textcoords="offset points",
                    ha="center", va="bottom", fontsize=8, color=INK)


def main():
    plt.rcParams["font.family"] = "Arial"
    fig, (a, b) = plt.subplots(1, 2, figsize=(6.3, 2.7), dpi=220,
                               gridspec_kw={"width_ratios": [1, 2.2], "wspace": 0.28})
    fig.patch.set_facecolor("white")

    # Panel A: accuracy of automatic verdicts
    acc = [pct(ONE["right"], ONE["auto"]), pct(TWO["right"], TWO["auto"])]
    bars = a.bar([0, 1], acc, width=0.55, color=[BLUE, ORANGE],
                 edgecolor="white", linewidth=1.5)
    label(a, bars)
    a.set_xticks([0, 1], ["One judge", "Two judges"])
    a.set_ylim(0, 105)
    a.set_yticks([0, 25, 50, 75, 100], ["0", "25", "50", "75", "100%"])
    a.set_title("Accuracy of automatic verdicts", fontsize=9, color=INK, loc="left", pad=8)
    style(a)

    # Panel B: outcomes as % of all 129 cases (same denominator)
    groups = ["False alarms", "Missed breaks", "Sent to human"]
    keys = ["false_alarms", "missed", "human"]
    x = range(len(groups))
    w = 0.36
    b1 = b.bar([i - w / 2 - 0.01 for i in x], [pct(ONE[k], CASES) for k in keys], w,
               color=BLUE, edgecolor="white", linewidth=1.5, label="One judge")
    b2 = b.bar([i + w / 2 + 0.01 for i in x], [pct(TWO[k], CASES) for k in keys], w,
               color=ORANGE, edgecolor="white", linewidth=1.5, label="Two judges")
    label(b, b1, "{:.1f}%")
    label(b, b2, "{:.1f}%")
    b.set_xticks(list(x), groups)
    b.set_ylim(0, 24)
    b.set_yticks([0, 5, 10, 15, 20], ["0", "5", "10", "15", "20%"])
    b.set_title("Share of all 129 cases", fontsize=9, color=INK, loc="left", pad=8)
    style(b)
    b.legend(frameon=False, fontsize=8, labelcolor=INK, loc="upper left",
             handlelength=1.0, handleheight=0.8)

    fig.text(0.01, -0.04,
             "New-task test, 129 attacks, author's blind labels. Two judges = second judge "
             "(Jev) checks every verdict, measured live.",
             fontsize=7, color=MUTED)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, bbox_inches="tight", facecolor="white")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
