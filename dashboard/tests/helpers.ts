import { screen, within } from '@testing-library/react';
import type { UserEvent } from '@testing-library/user-event';

export const currentLocation = () => screen.getByTestId('location').textContent;

export const pick = async (user: UserEvent, comboboxName: string | RegExp, option: string | RegExp) => {
  const comboboxes = await screen.findAllByRole('combobox', { name: comboboxName });
  await user.click(comboboxes[comboboxes.length - 1]);
  const listbox = screen.getByRole('listbox', { name: comboboxName });
  await user.click(within(listbox).getByRole('option', { name: option }));
};

export const file = (name: string, content = 'bytes', type = 'application/octet-stream') =>
  new File([content], name, { type });
