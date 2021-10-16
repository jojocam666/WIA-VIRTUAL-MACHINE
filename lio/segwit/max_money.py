
# Original block reward for miners is 1000 LIO = 50 0000 0000 lilio's
# Lio mining follows a predefined number of rules making the process very similar to the one in the traditionnal Centrals Banks
# Total amount of lios is 5 billion distributed in full to the miners-relayers who can introduce the currency in 4 ways on the blockchain:
#-or by putting it up for sale on the cryptx
#- or by storing it in the "bpsc-loan the wallet" where it will be distributed in the form of various credits and loans
#-or by using it for payments
#-or by blocking a certain amount in the form of a term deposit

start_block_reward = 50 * 10**8
# 420000 is around every 4 years with a 5 minute block interval
reward_interval = 420000


def max_money():
    current_reward = start_block_reward
    total = 0
    while current_reward > 0:
        total += reward_interval * current_reward
        current_reward /= 1.5
    return total


print("Total LIO to ever be created:", max_money(), "Lilio's")
