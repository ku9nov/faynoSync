import { setupServer } from 'msw/node';

export const API = 'http://localhost:3000';
export const server = setupServer();
