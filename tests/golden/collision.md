# Falsiq collision

- Case: <code>01ARZ3NDEKTSV4RRFFQ69G5FAV</code>
- Round: 1
- Reviews: 5

Rule every review with exactly one command shown below.

## R1 [boundary]

**Settles**

- <code>decision 0</code>

### Input

<pre>
empty file
&#x23; this must not become a heading
</pre>

### Forced choices

#### Choice A

<pre>
exit 0
</pre>

[Open choice artifact](../../../cases/01ARZ3NDEKTSV4RRFFQ69G5FAV/collisions/accept%20output.txt) — <code>cases/01ARZ3NDEKTSV4RRFFQ69G5FAV/collisions/accept output.txt</code>

#### Choice B

<pre>
exit 2: error
</pre>

### Risk scenario

<pre>
bad outcome 0
</pre>

### Legal rulings

```console
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FAX intended --choice A
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FAX intended --choice B
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FAX forbidden --choice A
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FAX forbidden --choice B
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FAX dont_care
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FAX amend --text "<replacement intent>"
```

## R2 [consequence]

**Settles**

- <code>decision 1</code>

### Scenario

<pre>
On day 30, the cache serves stale data.
</pre>

### Risk scenario

<pre>
bad outcome 1
</pre>

### Legal rulings

```console
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FAY intended
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FAY forbidden
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FAY dont_care
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FAY amend --text "<replacement intent>"
```

## R3 [prototype]

**Settles**

- <code>decision 2</code>

### Rival behaviors

[Open artifact](../../../cases/01ARZ3NDEKTSV4RRFFQ69G5FAV/collisions/prototype/transcript.md) — <code>cases/01ARZ3NDEKTSV4RRFFQ69G5FAV/collisions/prototype/transcript.md</code>

### Risk scenario

<pre>
bad outcome 2
</pre>

### Legal rulings

```console
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FAZ intended
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FAZ forbidden
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FAZ dont_care
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FAZ amend --text "<replacement intent>"
```

## R4 [conflict]

**Settles**

- <code>decision 3</code>

### Observable diff

<pre>
- current behavior
+ requested behavior
</pre>

### Risk scenario

<pre>
bad outcome 3
</pre>

### Legal rulings

```console
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FB0 intended
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FB0 forbidden
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FB0 dont_care
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FB0 amend --text "<replacement intent>"
```

## R5 [omission]

**Settles**

- <code>decision 4</code>

### Transcript

<pre>
$ tool --empty
error: empty input
</pre>

### Risk scenario

<pre>
bad outcome 4
</pre>

### Legal rulings

```console
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FB1 intended
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FB1 forbidden
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FB1 dont_care
falsiq rule 01ARZ3NDEKTSV4RRFFQ69G5FB1 amend --text "<replacement intent>"
```
