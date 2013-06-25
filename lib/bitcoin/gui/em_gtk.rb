# encoding: ascii-8bit

require "monitor"

module Gtk
  GTK_PENDING_BLOCKS = []
  GTK_PENDING_BLOCKS_LOCK = Monitor.new

  def Gtk.queue &block
    GTK_PENDING_BLOCKS_LOCK.synchronize do
      GTK_PENDING_BLOCKS << block
    end
  end

  def Gtk.main_iteration_with_queue
      GTK_PENDING_BLOCKS_LOCK.synchronize do
        for block in GTK_PENDING_BLOCKS
          block.call
        end
        GTK_PENDING_BLOCKS.clear
      end
    Gtk.main_iteration while Gtk.events_pending
  end
end

module EM
  def self.gtk_main
    EM.add_periodic_timer(0.001) { Gtk.main_iteration_with_queue }
  end
end
