import { Sequelize } from 'sequelize';

export function createSequelize(databaseUrl: string): Sequelize {
  return new Sequelize(databaseUrl, {
    dialect: 'postgres',
    logging: false,
    pool: { max: 10, min: 0, idle: 10_000, acquire: 15_000 },
  });
}
