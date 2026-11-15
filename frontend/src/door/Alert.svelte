<script lang="ts">
  // A message on the door: ink text, never red (ADR-0017 decision 1),
  // announced as an alert. Text only, never markup.
  import type { Message } from './messages'

  let { msg }: { msg: Message | null } = $props()
</script>

{#if msg}
  <p class="error" role="alert">{msg.text}{#if msg.aside}<br /><span>{msg.aside}</span>{/if}</p>
{/if}
