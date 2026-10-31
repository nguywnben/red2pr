"""Drain in-flight secret consumers before activating a rotated key ring."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager


class RotationDrain:
    """A cancellation-safe read gate: rotations stop new users and await active leases."""

    def __init__(self) -> None:
        self._condition = asyncio.Condition()
        self._active = 0
        self._rotating = False

    @asynccontextmanager
    async def operation(self) -> AsyncIterator[None]:
        async with self._condition:
            await self._condition.wait_for(lambda: not self._rotating)
            self._active += 1
        try:
            yield
        finally:
            async with self._condition:
                self._active -= 1
                self._condition.notify_all()

    @asynccontextmanager
    async def rotation(self) -> AsyncIterator[None]:
        async with self._condition:
            await self._condition.wait_for(lambda: not self._rotating)
            self._rotating = True
            try:
                await self._condition.wait_for(lambda: self._active == 0)
            except BaseException:
                self._rotating = False
                self._condition.notify_all()
                raise
        try:
            yield
        finally:
            async with self._condition:
                self._rotating = False
                self._condition.notify_all()
