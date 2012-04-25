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
          EM.next_tick { block.call }
        end
        GTK_PENDING_BLOCKS.clear
      end
    Gtk.main_iteration  if Gtk.events_pending?
  end
end

module EM
  def self.gtk_main
    give_tick = proc do
      Gtk.main_iteration_with_queue
      EM.defer do
        sleep 0.001
        EM.next_tick give_tick
      end
    end
    give_tick.call
  end
end
