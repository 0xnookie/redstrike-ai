// Deterministic circle packing — the front-chain algorithm behind d3.packSiblings
// (Bostock, ISC), ported inline so the console keeps zero chart dependencies.
//
// Given a list of radii it returns a centre {x,y} for each, laid out as a tight,
// non-overlapping cluster: the first circle sits at the origin and the rest spiral
// around it, so feeding the biggest/most-notable first keeps them central. Unlike a
// fixed-pitch sunflower, the placement accounts for every circle's actual radius, so
// nothing overlaps regardless of how much the sizes vary. No randomness → stable
// across renders.

type Circle = { r: number; x: number; y: number };

/** Position c tangent to a and b (c.r already set). */
function place(b: Circle, a: Circle, c: Circle): void {
  const dx = b.x - a.x, dy = b.y - a.y, d2 = dx * dx + dy * dy;
  if (d2) {
    const a2 = (a.r + c.r) * (a.r + c.r);
    const b2 = (b.r + c.r) * (b.r + c.r);
    if (a2 > b2) {
      const x = (d2 + b2 - a2) / (2 * d2);
      const y = Math.sqrt(Math.max(0, b2 / d2 - x * x));
      c.x = b.x - x * dx - y * dy;
      c.y = b.y - x * dy + y * dx;
    } else {
      const x = (d2 + a2 - b2) / (2 * d2);
      const y = Math.sqrt(Math.max(0, a2 / d2 - x * x));
      c.x = a.x + x * dx - y * dy;
      c.y = a.y + x * dy + y * dx;
    }
  } else {
    c.x = a.x + c.r;
    c.y = a.y;
  }
}

function intersects(a: Circle, b: Circle): boolean {
  const dr = a.r + b.r - 1e-6, dx = b.x - a.x, dy = b.y - a.y;
  return dr > 0 && dr * dr > dx * dx + dy * dy;
}

class LNode {
  _: Circle;
  next: LNode | null = null;
  previous: LNode | null = null;
  constructor(c: Circle) { this._ = c; }
}

/** Squared distance from the origin to the weighted midpoint of a node and its successor. */
function score(node: LNode): number {
  const a = node._, b = node.next!._, ab = a.r + b.r;
  const dx = (a.x * b.r + b.x * a.r) / ab;
  const dy = (a.y * b.r + b.y * a.r) / ab;
  return dx * dx + dy * dy;
}

/** Lay out circles of the given radii with no overlaps; returns a centre per input. */
export function packSiblings(radii: number[]): Array<{ x: number; y: number }> {
  const n = radii.length;
  const circles: Circle[] = radii.map((r) => ({ r, x: 0, y: 0 }));
  if (n === 0) return [];

  const c0 = circles[0]; c0.x = 0; c0.y = 0;
  if (n > 1) {
    const c1 = circles[1];
    c0.x = -c1.r; c1.x = c0.r; c1.y = 0;
    if (n > 2) {
      place(c1, c0, circles[2]);

      // Seed the front-chain with the first three circles.
      let nA = new LNode(c0), nB = new LNode(c1);
      const nC = new LNode(circles[2]);
      nA.next = nC.previous = nB;
      nB.next = nA.previous = nC;
      nC.next = nB.previous = nA;

      pack: for (let i = 3; i < n; ++i) {
        const ci = circles[i];
        place(nA._, nB._, ci);
        const node = new LNode(ci);

        // Walk the chain from both ends; if the new circle hits one, that becomes a
        // new chain end and we retry placing this same circle against it.
        let j = nB.next!, k = nA.previous!, sj = nB._.r, sk = nA._.r;
        do {
          if (sj <= sk) {
            if (intersects(j._, node._)) { nB = j; nA.next = nB; nB.previous = nA; --i; continue pack; }
            sj += j._.r; j = j.next!;
          } else {
            if (intersects(k._, node._)) { nA = k; nA.next = nB; nB.previous = nA; --i; continue pack; }
            sk += k._.r; k = k.previous!;
          }
        } while (j !== k.next);

        // Insert the circle and advance the chain to the pair closest to the centre.
        node.previous = nA; node.next = nB; nA.next = nB.previous = nB = node;
        let aa = score(nA), scan = node;
        while ((scan = scan.next!) !== nB) {
          const ca = score(scan);
          if (ca < aa) { nA = scan; aa = ca; }
        }
        nB = nA.next!;
      }
    }
  }

  return circles.map((c) => ({ x: c.x, y: c.y }));
}
