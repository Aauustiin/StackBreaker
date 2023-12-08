import Fuzzer.binary_spy as binary_spy

import random
import math
import statistics

alphabet = 'abcdefghijklmnopqrstvwxyz\n\''
alphabet += 'ABCDEFGHIJKLMNOPQRSTUVXYZ'
alphabet += '0123456789'
alphabet += '%\\\n'

def initialisePop(pop_size: int, genome_length: tuple[int, int], genetic_alphabet) -> list:
    pop = []

    while len(pop) < pop_size:
        individual_len = random.randrange(genome_length[0], genome_length[1])
        solution = ''.join(random.choice(genetic_alphabet) for _ in range(individual_len))
        pop.append({'fitness':None, 'solution':solution})

    return pop

def assess(pop: list, target: list[int]):
    for i, individual in enumerate(pop):
        print(f'Assessing {i+1} of {len(pop)}...', end='\r')
        score = binary_spy.score(bytes(individual['solution'], 'utf-8'), target)
        pop[i]['fitness'] = score
    ret = sorted(pop, key=lambda i: i['fitness'], reverse=True)
    
    return ret
    
def tournament(pop, tournament_size):
    competitors = random.sample(pop, tournament_size)

    winner = competitors.pop()
    while competitors:
        i = competitors.pop()
        if i['fitness'] > winner['fitness']:
            winner = i

    return winner['solution']

def cross(mum: str, dad: str):
    offspring_len = math.ceil( (len(mum)+ len(dad)) / 2)

    offsping = ''
    i = 0
    for m,d in zip(mum, dad):
        i += 1
        if random.choice([True, False]):
            offsping += m
        else:
            offsping += d

    if len(mum) > len(dad):
        offsping += mum[i:offspring_len]
    else:
        offsping += dad[i:offspring_len]

    return offsping

def breed(pop, tournament_size, crossover):
    offspring_pop = []

    elite = pop[0]
    offspring_pop.append({'fitness': None, 'solution': elite['solution']})

    while len(offspring_pop) < len(pop):
        mum = tournament(pop, tournament_size)
        if random.random() < crossover:
            dad = tournament(pop, tournament_size)
            offspring_solution = cross(mum, dad)
            offspring_pop.append({'fitness': None, 'solution':offspring_solution})
        else:
            offspring_pop.append({'fitness': None, 'solution': mum})

    return offspring_pop


def mutate(pop,alphabet):
    for i in pop[1:]:
        length = len(i['solution'])
        for j in range(length):
            mutation = 1/length
            if random.random() < mutation:
                i['solution'] = i['solution'][:j] + random.choice(alphabet)\
                                + i['solution'][j:]
                
    return pop
    
def checkStagnation(top_fitness):
    length = len(top_fitness)
    if length < 3: return False
    if top_fitness[-1] == top_fitness[-2] and top_fitness[-2] == top_fitness[-3]:
        return True
    return False

def freshenPop(pop:list, genome_len, alphabet):
    popLen = len(pop)
    bestSolLen = len(pop[0]['solution'])
    sameLenPop = initialisePop(int(popLen/4), (bestSolLen, bestSolLen+1), alphabet)
    randLenPop = initialisePop(int(popLen/4), genome_len, alphabet)

    pop = pop[:popLen - int(popLen/4)*2].copy()
    pop.extend(sameLenPop)
    pop.extend(randLenPop)

    return pop

def writeFitness(pop, gen):
    fitness = [i['fitness'] for i in pop]
    solutions = [i['solution'] for i in pop]

    print('Gen {:4d}: max fit - {:.3f}, min fit - {:.3f}, mean - {:.3f}, stdev - {:.3f}'\
          .format(gen, fitness[0], fitness[-1], statistics.mean(fitness), statistics.stdev(fitness))
          )
    print(f'Average solution length: {statistics.median([len(s) for s in solutions])}')
    print(f'Best solution:\n<{pop[0]["solution"]}>')

    print()


def run_the_ga(target, alphabet=alphabet, pop_size=50, genome_length=(5,1024), tournament_size=10, crossover=0.3, max_gen=1000, 
               write_every=1):
    random.seed()

    pop = initialisePop(pop_size, genome_length, alphabet)
    pop = assess(pop, target)
    writeFitness(pop, 0)


    generation = 0
    best = pop[0]
    top_fitenss = [best['fitness']]
    while generation < max_gen and best['fitness'] < 1:
        pop = breed(pop, tournament_size, crossover)
        pop = mutate(pop, alphabet)
        if checkStagnation(top_fitenss):
            pop = freshenPop(pop, genome_length ,alphabet)
        generation += 1
        pop = assess(pop, target)
        best = pop[0]
        top_fitenss.append(best['fitness'])

        if write_every and generation % write_every == 0:
            writeFitness(pop, generation)

    return generation, best  

def get_random_string(min, max):
    length = random.randrange(min, max)
    ret = ''.join(random.choice(alphabet) for _ in range(length))
    return ret