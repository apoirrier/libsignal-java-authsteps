import matplotlib
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
import numpy as np
import scipy.stats as st

font = {'size'   : 17}

matplotlib.rc('font', **font)

rates = ['90','95','99']

for rate in rates:
    first = True
    ctxtSizeOriginal = []
    sessionSizeOriginal = []
    currentCtxtSize = []
    currentSessionSize = []
    xCtxt = []
    xSession = []
    with open("outputOriginal" + rate + ".log") as f:
        for l in f:
            if first:
                first = False
                continue
            if "seed" in l:
                ctxtSizeOriginal += currentCtxtSize
                sessionSizeOriginal += currentSessionSize
                xCtxt.append(np.mean(currentCtxtSize))
                xSession.append(np.mean(currentSessionSize))
                currentCtxtSize = []
                currentSessionSize = []
                continue
            split = l.split(' ')
            currentCtxtSize.append(int(split[2]))
            currentSessionSize.append((int(split[3]) + int(split[4])) / 2)

    ctxtConfidenceOriginal = st.t.interval(0.95, len(xCtxt)-1, loc=np.mean(xCtxt), scale=st.sem(xCtxt))
    sessionConfidenceOriginal = st.t.interval(0.95, len(xSession)-1, loc=np.mean(xSession), scale=st.sem(xSession))

    first = True
    ctxtSizeAuthStep = []
    sessionSizeAuthStep = []
    currentCtxtSize = []
    currentSessionSize = []
    xCtxt = []
    xSession = []
    with open("outputAuthStep" + rate + ".log") as f:
        for l in f:
            if first:
                first = False
                continue
            if "seed" in l:
                ctxtSizeAuthStep += currentCtxtSize
                sessionSizeAuthStep += currentSessionSize
                xCtxt.append(np.mean(currentCtxtSize))
                xSession.append(np.mean(currentSessionSize))
                currentCtxtSize = []
                currentSessionSize = []
                continue
            split = l.split(' ')
            currentCtxtSize.append(int(split[2]))
            currentSessionSize.append((int(split[3]) + int(split[4])) / 2)

    ctxtConfidenceAuthStep = st.t.interval(0.95, len(xCtxt)-1, loc=np.mean(xCtxt), scale=st.sem(xCtxt))
    sessionConfidenceAuthStep = st.t.interval(0.95, len(xSession)-1, loc=np.mean(xSession), scale=st.sem(xSession))

    plt.figure()
    fig, ax = plt.subplots(1, 2, sharey=True, figsize=(15,5))
    ctxtSizeOriginal.sort()
    ctxtSizeAuthStep.sort()
    ax[0].step(ctxtSizeOriginal, 100 * np.arange(len(ctxtSizeOriginal)) / len(ctxtSizeOriginal), color='lightblue')
    ax[0].step(ctxtSizeAuthStep, 100 * np.arange(len(ctxtSizeAuthStep)) / len(ctxtSizeAuthStep), color='orange')
    ax[0].axvline(x=np.mean(ctxtSizeOriginal), color='lightblue', ls='--')
    ax[0].axvline(x=np.mean(ctxtSizeAuthStep), color='orange', ls='--')
    ax[0].axvspan(ctxtConfidenceOriginal[0], ctxtConfidenceOriginal[1], alpha=0.3, color='lightblue')
    ax[0].axvspan(ctxtConfidenceAuthStep[0], ctxtConfidenceAuthStep[1], alpha=0.3, color='orange')
    # ax[0].hist(ctxtSizeOriginal, cumulative=True, bins=50, alpha=0.5, color='lightblue', label='Original')
    # ax[0].hist(ctxtSizeAuthStep, cumulative=True, bins=50, alpha=0.5, color='orange', label='AuthStep')
    ax[0].set_xlim((0, 400))
    ax[0].set_ylim((0,100))
    ax[0].set_xlabel("Ciphertext size (bytes)")
    ax[0].set_ylabel("Cumulative frequency")
    ax[0].yaxis.set_major_formatter(mtick.PercentFormatter())

    #ax[1].hist(sessionSizeOriginal, cumulative=True, bins=50, alpha=0.5, color='lightblue', label='Original')
    #ax[1].hist(sessionSizeAuthStep, cumulative=True, bins=50, alpha=0.5, color='orange', label='AuthStep')
    sessionSizeAuthStep.sort()
    sessionSizeOriginal.sort()
    ax[1].step(sessionSizeOriginal, 100 * np.arange(len(sessionSizeOriginal)) / len(sessionSizeOriginal), color='lightblue', label='Original')
    ax[1].step(sessionSizeAuthStep, 100 * np.arange(len(sessionSizeAuthStep)) / len(sessionSizeAuthStep), color='orange', label='AuthStep')
    ax[1].axvline(x=np.mean(sessionSizeOriginal), color='lightblue', ls='--')
    ax[1].axvline(x=np.mean(sessionSizeAuthStep), color='orange', ls='--')
    ax[1].axvspan(sessionConfidenceOriginal[0], sessionConfidenceOriginal[1], alpha=0.3, color='lightblue')
    ax[1].axvspan(sessionConfidenceAuthStep[0], sessionConfidenceAuthStep[1], alpha=0.3, color='orange')
    ax[1].set_xlim((0, 6000))
    ax[1].set_xlabel("Session's state size (bytes)")

    legend_size = 0.26
    handles, labels = ax[0].get_legend_handles_labels()
    l0 = ax[0].axvline(x=-1, color='black')
    l1 = ax[0].axvline(x=-1, color='black', ls='--')
    l2 = ax[0].axvspan(-1, -0.5, color='black', alpha=0.3)
    fig.legend([l0, l1, l2],
               ['Cumulative frequency', 'Mean', '95% confidence interval'],
               loc="lower center",
               bbox_to_anchor=(1 - legend_size / 2, 0.52),
               borderaxespad=0.1,
               title="Line type")
    l0 = ax[0].scatter([-1], [-1], color='lightblue')
    l1 = ax[0].scatter([-1], [-1], color='orange')
    fig.legend([l0, l1],
               ['Original', 'AuthStep'],
               loc="upper center",
               bbox_to_anchor=(1 - legend_size / 2, 0.48),
               borderaxespad=0.1,
               title="Colors")
    plt.subplots_adjust(right=1 - legend_size, bottom=0.2, left=0.1, top=0.95)

    plt.savefig("comparison" + rate + ".pdf")

## Comparing channel reliability

first = True
x = []
sessionSizeOriginal = []
ctxtSizeOriginal = []
with open("outputOriginalDrop.log") as f:
    for l in f:
        if first:
            first = False
            continue
        split = l.split(' ')
        x.append(float(split[1]))
        ctxtSizeOriginal.append(int(split[2]))
        sessionSizeOriginal.append(int(split[3]))

first = True
sessionSizeAuthStep = []
ctxtSizeAuthStep = []
with open("outputAuthStepDrop.log") as f:
    for l in f:
        if first:
            first = False
            continue
        split = l.split(' ')
        ctxtSizeAuthStep.append(int(split[2]))
        sessionSizeAuthStep.append(int(split[3]))

plt.figure()
fig, ax1 = plt.subplots()
p1 = ax1.plot(x, sessionSizeOriginal, color='tab:red', label='Original session size', ls='--')
p2 = ax1.plot(x, sessionSizeAuthStep, color='tab:red', label='AuthStep session size')
ax1.set_xlabel("Channel reliability")
ax1.set_ylabel("Average session size (bytes)", color='tab:red')
ax1.tick_params(axis='y', labelcolor='tab:red')

ax2 = ax1.twinx()
p3 = ax2.plot(x, ctxtSizeOriginal, color='tab:blue', label='Original ciphertext size', ls='--')
p4 = ax2.plot(x, ctxtSizeAuthStep, color='tab:blue', label='AuthStep ciphertext size')
ax2.set_ylabel("Average ciphertext size (bytes)", color='tab:blue')
ax2.tick_params(axis='y', labelcolor='tab:blue')

p = p1+p2+p3+p4
labels = [l.get_label() for l in p]
ax1.legend(p, labels)

fig.tight_layout()
plt.savefig("dropComparison.pdf")

## Comparing epoch length

first = True
x = []
sessionSizeOriginal = []
with open("outputOriginalNb.log") as f:
    for l in f:
        if first:
            first = False
            continue
        split = l.split(' ')
        x.append(float(split[0]))
        sessionSizeOriginal.append(int(split[3]))

first = True
sessionSizeAuthStep = []
with open("outputAuthStepNb.log") as f:
    for l in f:
        if first:
            first = False
            continue
        split = l.split(' ')
        sessionSizeAuthStep.append(int(split[3]))

plt.figure()
plt.plot(x, sessionSizeOriginal, color='lightblue', label='Original', ls='--')
plt.plot(x, sessionSizeAuthStep, color='orange', label='AuthStep')
plt.xlabel("Average epoch length")
plt.ylabel("Average session size (bytes)")
plt.legend()
plt.tight_layout()
plt.savefig("nbComparison.pdf")