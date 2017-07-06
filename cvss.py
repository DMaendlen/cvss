#!/usr/bin/python3

'''
This program calculates a CVSSv3 base, temporal and environmental score.
Metrics, Calculations and Values taken from:
    https://www.first.org/cvss/specification-document
'''

from math import ceil

class CvssV3Calculator():
    '''Calculate a CVSSv3 base score'''

    def __init__(self):
        '''Initialize the object'''
        self.scope_changed = False
        self.values = None
        self.basestring = None
        self.metric_levels = {
            'AV': {             # attack vector
                   'N': 0.85,   # network
                   'A': 0.62,   # adjacent network
                   'L': 0.55,   # local
                   'P': 0.2     # physical
                  },
            'AC': {             # attack complexity
                   'L': 0.77,   # low
                   'H': 0.44    # high
                  },
            'PR': {             # privilege required
                   'N': 0.85,   # none
                   'L': 0.62,   # low
                   'H': 0.27    # high
                  },
            'UI': {             # user interaction
                   'N': 0.85,   # none
                   'R': 0.62    # required
                  },
            'C': {              # confidentiality
                'H': 0.56,      # high
                'L': 0.22,      # low
                'N': 0          # none
                },
            'I': {              # integrity
                'H': 0.56,      # high
                'L': 0.22,      # low
                'N': 0          # none
                },
            'A': {              # availability
                'H': 0.56,      # high
                'L': 0.22,      # low
                'N': 0}         # none
        }


    def get_base_values(self):
        '''Interactive UI for getting the needed values for a base score'''

        attack_vector = None
        attack_complexity = None
        privileges_required = None
        user_interaction = None
        scope = None
        confidentiality = None
        integrity = None
        availability = None

        while attack_vector not in ['N', 'A', 'L', 'P']:
            attack_vector = input('''Attack Vector. [N]etwork, [A]djacent Network, [L]ocal or [P]hysical: ''').upper()

        while attack_complexity not in ['L', 'H']:
            attack_complexity = input('''Attack Complexity. [L]ow or [H]igh: ''').upper()

        while privileges_required not in ['N', 'L', 'H']:
            privileges_required = input('''Privileges required. [N]one, [L]ow or [H]igh: ''').upper()

        while user_interaction not in ['N', 'R']:
            user_interaction = input('''User interaction. [N]one or [R]equired: ''').upper()

        while scope not in ['C', 'U']:
            scope = input('''Scope [C]hanged or [U]nchanged: ''').upper()
            if scope == 'C':
                self.scope_changed = True
            elif scope == 'U':
                self.scope_changed = False

        while confidentiality not in ['H', 'L', 'N']:
            confidentiality = input('''Confidentiality impact. [H]igh, [L]ow, [N]one: ''').upper()

        while integrity not in ['H', 'L', 'N']:
            integrity = input('''Integrity impact. [H]igh, [L]ow, [N]one: ''').upper()

        while availability not in ['H', 'L', 'N']:
            availability = input('''Availability impact. [H]igh, [L]ow, [N]one: ''').upper()

        if self.scope_changed:
            self.metric_levels['PR']['L'] = 0.68
            self.metric_levels['PR']['H'] = 0.50

        self.values = {
            'AV': self.metric_levels['AV'][attack_vector],
            'AC': self.metric_levels['AC'][attack_complexity],
            'PR': self.metric_levels['PR'][privileges_required],
            'UI': self.metric_levels['UI'][user_interaction],
            'C': self.metric_levels['C'][confidentiality],
            'I': self.metric_levels['I'][integrity],
            'A': self.metric_levels['A'][availability],
        }

        self.base_string = 'CVSS:3.0/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}'.format(
            av=attack_vector,
            ac=attack_complexity,
            pr=privileges_required,
            ui=user_interaction,
            s=scope,
            c=confidentiality,
            i=integrity,
            a=availability)


    def calculate_exploitability_subscore(self):
        '''
        Returns Exploitabiltiy, calculated by
        8.22 x AV x AC x PR x UI
        '''

        return 8.22 * self.values['AV'] * self.values['AC'] * self.values['PR'] * self.values['UI']

    def calculate_impact_subscore(self):
        '''
        For an explanation of this return value please see the specification document
        '''
        impact_c = self.values['C']
        impact_i = self.values['I']
        impact_a = self.values['A']

        isc_base = 1 - ((1 - impact_c) * (1 - impact_i) * (1 - impact_a))

        if self.scope_changed:
            return 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02)**15
        else:
            return 6.42 * isc_base

    def calculate_base_score(self):
        '''Calculate base score from exploitability and impact sub scores.'''

        impact = self.calculate_impact_subscore()
        exploitability = self.calculate_exploitability_subscore()

        if impact <= 0:
            return 0

        if self.scope_changed:
            return min(ceil((1.08 * (impact + exploitability))*10)/10, 10)
        else:
            return min(ceil((impact + exploitability)*10)/10, 10)

    def base_vector(self):
        '''Get values, calculate the score and print score and base string'''

        self.get_base_values()
        print(self.calculate_base_score(), self.base_string)

if __name__ == '__main__':
    vector = None
    calculator = CvssV3Calculator()
    while vector not in ['B', 'T', 'E']:
        vector = input('''Do you want to calculate a [B]ase, [T]emporal or [E]nvironmental score? ''').upper()

    if vector == 'B':
        calculator.base_vector()
    elif vector == 'T':
        print('Sorry, not yet implemented')
    elif vector == 'E':
        print('Sorry, not yet implemented')
    else:
        print('Something went very, very wrong.')
