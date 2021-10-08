
# Original block reward for miners is 1000 LIO = 50 0000 0000 lilio's
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
