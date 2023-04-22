# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# This file should be checked into the version control system.

ActiveRecord::Schema[7.0].define(version: 2018_01_26_153804) do # rubocop:disable Style/NumericLiterals
  create_table 'users', force: :cascade do |t|
    t.string 'username'
    t.string 'encrypted_password'
    t.datetime 'created_at', precision: nil, null: false
    t.datetime 'updated_at', precision: nil, null: false
  end
end
