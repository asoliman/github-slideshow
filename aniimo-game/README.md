# Monster Trek: Card Clash

A 2D card battler built from the Monster Trek / Aniimo-inspired creature roster. No map or walking around — it's a head-to-head card game against a computer opponent.

## Play

Open `index.html` in any browser. No build step or server required.

## How it works

- Each side has a 24-card deck (2 copies of each of 12 creatures), a hand, and a board.
- Energy increases by 1 each of your turns (cap 8); creature cards cost energy to play.
- A creature played this turn is "resting" and can't attack until your next turn.
- On your turn, select a ready creature on your board, then click an enemy creature (to fight it) or the opponent's board area (to hit them directly).
- Type effectiveness applies: fire > grass > water > fire, electric > water, rock > fire, rock > electric (effective hits do 1.5x, resisted hits do 0.6x).
- Reduce the opponent's life to 0, or outlast them if they run out of cards, to win.
